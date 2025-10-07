#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "CertificateManager.hpp"
// Use namespaces for cleaner code
namespace ssl = boost::asio::ssl;
using boost::asio::ip::tcp;

/**
 * @class session
 * @brief Handles a single proxy connection (one browser talking to one server).
 *
 * This class manages its own lifecycle using std::shared_ptr. For each new
 * browser connection, a 'session' object is created. It reads the HTTP request,
 * connects to the destination server, and then relays data in both directions.
 */
class session : public std::enable_shared_from_this<session>
{
public:
    session(tcp::socket browser_socket, ssl::context &client_ctx)
        : browser_stream_(std::move(browser_socket), CertificateManager::get_server_context("dummy")), // Placeholder context
          server_stream_(browser_stream_.get_executor(), client_ctx)
    {
    }

    void start()
    {
        std::cout << "hello" << std::endl;
        read_request_line();
    }

private:
    void read_request_line()
    {
        auto self = shared_from_this();
        boost::asio::async_read_until(browser_stream_.next_layer(), request_buffer_, "\r\n",
                                      [this, self](const boost::system::error_code &ec, std::size_t bytes)
                                      {
                                          if (!ec)
                                          {
                                              std::istream request_stream(&request_buffer_);
                                              std::string method, target, version;
                                              request_stream >> method >> target >> version;

                                              if (method == "CONNECT")
                                              {
                                                  host_ = target.substr(0, target.find(":"));
                                                  port_ = target.substr(target.find(":") + 1);
                                                  connect_to_server();
                                              }
                                              else
                                              {
                                                  // Handling plain HTTP is more complex in an MITM proxy and is omitted for clarity.
                                                  std::cerr << "Non-CONNECT requests not supported in this example.\n";
                                              }
                                          }
                                      });
    }

    void connect_to_server()
    {
        auto self = shared_from_this();
        tcp::resolver resolver(browser_stream_.get_executor());
        resolver.async_resolve(host_, port_,
                               [this, self](const boost::system::error_code &ec, tcp::resolver::results_type results)
                               {
                                   if (!ec)
                                   {
                                       boost::asio::async_connect(server_stream_.lowest_layer(), results,
                                                                  [this, self](const boost::system::error_code &ec, const tcp::endpoint &ep)
                                                                  {
                                                                      if (!ec)
                                                                      {
                                                                          send_connect_success_response();
                                                                      }
                                                                  });
                                   }
                               });
    }

    void send_connect_success_response()
    {
        auto self = shared_from_this();
        const std::string response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        boost::asio::async_write(browser_stream_.next_layer(), boost::asio::buffer(response),
                                 [this, self](const boost::system::error_code &ec, std::size_t bytes)
                                 {
                                     if (!ec)
                                     {
                                         // TCP tunnel is set up, now perform TLS handshakes on both sides.
                                         perform_handshakes();
                                     }
                                 });
    }

    void perform_handshakes()
    {
        // Before browser handshake, set the correct SSL context for the requested hostname
        SSL_set_SSL_CTX(browser_stream_.native_handle(), CertificateManager::get_server_context(host_).native_handle());

        // Perform server-side (browser) handshake
        browser_stream_.async_handshake(ssl::stream_base::server,
                                        [self = shared_from_this()](const boost::system::error_code &ec)
                                        {
                                            if (!ec)
                                            {
                                                self->on_handshake_complete();
                                            }
                                            else
                                            {
                                                std::cerr << "Browser handshake failed: " << ec.message() << "\n";
                                            }
                                        });

        if (!SSL_set_tlsext_host_name(server_stream_.native_handle(), host_.c_str()))
        {
            boost::system::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
            std::cerr << "Failed to set SNI hostname: " << ec.message() << "\n";
            return;
        }
        // Set the verification callback to check the hostname
        server_stream_.set_verify_callback(ssl::host_name_verification(host_));

        // Perform client-side (server) handshake
        server_stream_.async_handshake(ssl::stream_base::client,
                                       [self = shared_from_this()](const boost::system::error_code &ec)
                                       {
                                           if (!ec)
                                           {
                                               self->on_handshake_complete();
                                           }
                                           else
                                           {
                                               std::cerr << "Server handshake failed: " << ec.message() << "\n";
                                           }
                                       });
    }

    void on_handshake_complete()
    {
        handshakes_done_++;
        if (handshakes_done_ == 2)
        {
            std::cout << "--> MITM tunnels established for " << host_ << ". Relaying decrypted data.\n";
            // Both handshakes complete, start relaying decrypted data
            relay(browser_stream_, server_stream_, browser_to_server_buffer_);
            relay(server_stream_, browser_stream_, server_to_browser_buffer_);
        }
    }

    template <typename From, typename To, typename Buffer>
    void relay(From &from, To &to, Buffer &buffer)
    {
        from.async_read_some(boost::asio::buffer(buffer),
                             [this, &from, &to, &buffer](const boost::system::error_code &ec, std::size_t bytes)
                             {
                                 if (!ec)
                                 {
                                     // Log the decrypted data
                                     std::cout << "--> Relaying " << bytes << " decrypted bytes for " << host_ << "\n";
                                     std::cout.write(buffer.data(), bytes);
                                     std::cout << "\n--------------------------------\n";

                                     async_write(to, boost::asio::buffer(buffer, bytes),
                                                 [this, &from, &to, &buffer](const boost::system::error_code &ec, std::size_t bytes)
                                                 {
                                                     if (!ec)
                                                     {
                                                         relay(from, to, buffer); // Continue the loop
                                                     }
                                                 });
                                 }
                             });
    }

    ssl::stream<tcp::socket> browser_stream_;
    ssl::stream<tcp::socket> server_stream_;
    boost::asio::streambuf request_buffer_;
    std::string host_, port_;
    int handshakes_done_ = 0;
    std::array<char, 8192> browser_to_server_buffer_;
    std::array<char, 8192> server_to_browser_buffer_;
};

/**
 * @class server
 * @brief Listens for incoming connections and creates a 'session' for each.
 */
class server
{
public:
    server(boost::asio::io_context &io_context, unsigned short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
          client_ctx_(ssl::context::tls_client)
    {
        // Set up context for connecting to servers (client-side)
        client_ctx_.set_default_verify_paths();
        client_ctx_.set_verify_mode(ssl::verify_peer);
        start_accept();
    }

private:
    void start_accept()
    {
        acceptor_.async_accept(
            [this](const boost::system::error_code &ec, tcp::socket socket)
            {
                if (!ec)
                {
                    std::cout << "hi" << std::endl;
                    std::make_shared<session>(std::move(socket), client_ctx_)->start();
                }
                start_accept();
            });
    }
    tcp::acceptor acceptor_;
    ssl::context client_ctx_;
};

int main(int argc, char *argv[])
{
    try
    {
        CertificateManager::init_ca("rootCA.pem", "rootCA.key");

        boost::asio::io_context io_context;
        server s(io_context, 8080);
        io_context.run();
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}