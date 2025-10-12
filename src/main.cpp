#include <bits/stdc++.h>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "CertificateManager.hpp"
#include "EncodingUtils.hpp"
#include "DatabaseManager.hpp"

// Use namespaces for cleaner code
namespace ssl = boost::asio::ssl;
using boost::asio::ip::tcp;

DatabaseManager g_db_manager; // Global database manager instance
class session;

// Global state to enable/disable interception
std::atomic<bool> g_intercept_on(false);

// A simple counter to generate unique IDs for each session
std::atomic<uint64_t> g_session_id_counter(0);

// Global map to hold active sessions, allowing external control (e.g., from a CLI)
// We use a weak_ptr to avoid preventing sessions from being destroyed.
std::mutex g_sessions_mutex;
std::unordered_map<uint64_t, std::weak_ptr<session>> g_sessions;

// A function to parse a raw HTTP message string
ParsedHttpData parse_http_message(const std::string &raw_message)
{
    ParsedHttpData result;
    std::istringstream stream(raw_message);
    std::string line;

    // 1. Read the start-line (e.g., "GET / HTTP/1.1")
    std::getline(stream, result.start_line);
    if (!result.start_line.empty() && result.start_line.back() == '\r')
    {
        result.start_line.pop_back();
    }

    // 2. Read headers until we hit a blank line
    while (std::getline(stream, line) && !line.empty() && line != "\r")
    {
        if (line.back() == '\r')
        {
            line.pop_back();
        }
        size_t colon_pos = line.find(": ");
        if (colon_pos != std::string::npos)
        {
            std::string key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 2);
            result.headers[key] = value;
        }
    }

    // 3. The rest of the stream is the body
    if (stream.good())
    {
        result.body = stream.str().substr(stream.tellg());
    }
    else
    {
        result.body = ""; // The stream is at the end, so there's no body.
    }

    return result;
}

// A function to print the parsed data to the console
void print_parsed_message(const ParsedHttpData &parsed_data, const std::string &message_type)
{
    std::cout << "\n\n--- PARSED " << message_type << " ---" << std::endl;

    // Print Start Line
    std::cout << "Start-Line: " << parsed_data.start_line << std::endl;

    // Print Headers
    std::cout << "\n[ Headers ]" << std::endl;
    for (const auto &pair : parsed_data.headers)
    {
        std::cout << pair.first << ": " << pair.second << std::endl;
    }

    // Print Body (if it exists)
    if (!parsed_data.body.empty())
    {
        auto it = parsed_data.headers.find("Content-Encoding");
        if (it != parsed_data.headers.end() && it->second.find("gzip") != std::string::npos)
        {
            std::cout << "\n[ Body (Gzip Decompressed) ]" << std::endl;
            try
            {
                std::cout << gzip_decompress(parsed_data.body);
            }
            catch (const std::exception &e)
            {
                std::cout << "[Decompression failed: " << e.what() << "]";
            }
        }
        else
        {
            std::cout << "\n[ Body ]" << std::endl;
            std::cout << parsed_data.body;
        }
    }
    std::cout << "\n--- END PARSED " << message_type << " ---\n\n"
              << std::endl;
}

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
        : browser_stream_(std::move(browser_socket), CertificateManager::get_server_context("dummy")),
          server_stream_(browser_stream_.get_executor(), client_ctx),
          resolver_(browser_stream_.get_executor()),
          session_id_(++g_session_id_counter)
    {
        std::cout << " New session created with ID: " << session_id_ << std::endl;
    }

    ~session()
    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        g_sessions.erase(session_id_);
        std::cout << " Session with ID " << session_id_ << " destroyed." << std::endl;
    }

    uint64_t get_id() const
    {
        return session_id_;
    }

    void start()
    {
        read_request_line();
    }

    void forward(std::string modified_data)
    {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            if (!paused_)
                return; // Can't forward if not paused
            std::cout << "[API] Forwarding session " << session_id_ << std::endl;
            modified_data_ = std::move(modified_data);
            paused_ = false; // Set paused to false to unblock the waiting thread
        }
        cv_.notify_one(); // Notify the waiting relay thread
    }

    void drop()
    {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            std::cout << "[API] Dropping session " << session_id_ << std::endl;
            dropped_ = true;
            if (paused_)
            {
                paused_ = false; // Unpause the thread so it can process the drop
                cv_.notify_one();
            }
            else
            {
                // If the session wasn't paused, we can terminate it directly.
                terminate();
            }
        }
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
                                                  size_t colon_pos = target.find(":");
                                                  if (colon_pos != std::string::npos)
                                                  {
                                                      // Colon was found, parse host and port
                                                      host_ = target.substr(0, colon_pos);
                                                      port_ = target.substr(colon_pos + 1);
                                                  }
                                                  else
                                                  {
                                                      // No port specified, assume default HTTPS port 443
                                                      host_ = target;
                                                      port_ = "443";
                                                  }
                                                  connect_to_server();
                                              }
                                              else
                                              {
                                                  // Handling plain HTTP is more complex in an MITM proxy and is omitted for clarity.
                                                  std::cerr << "Non-CONNECT requests not supported in this example.\n";
                                              }
                                          }
                                          else
                                          {
                                              std::cerr << "[SESSION] ERROR 1: Failed to read from browser: " << ec.message() << std::endl;
                                          }
                                      });
    }

    void connect_to_server()
    {
        auto self = shared_from_this();
        resolver_.async_resolve(host_, port_,
                                [this, self](const boost::system::error_code &ec, tcp::resolver::results_type results)
                                {
                                    if (!ec)
                                    {
                                        // On successful DNS resolution, try to connect to the resolved endpoints.
                                        boost::asio::async_connect(server_stream_.lowest_layer(), results,
                                                                   [this, self](const boost::system::error_code &ec, const tcp::endpoint &ep)
                                                                   {
                                                                       if (!ec)
                                                                       {
                                                                           send_connect_success_response(); // Proceed to the next step
                                                                       }
                                                                       else
                                                                       {
                                                                           std::cerr << "[SESSION] ERROR 2a: Failed to connect to target: " << ec.message() << std::endl;
                                                                       }
                                                                   });
                                    }
                                    else
                                    {
                                        std::cerr << "[SESSION] ERROR 2: Failed to resolve hostname: " << ec.message() << std::endl;
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
                                         perform_handshakes();
                                     }
                                     else
                                     {
                                         std::cerr << "[SESSION] ERROR 3: Failed to write to browser: " << ec.message() << std::endl;
                                     }
                                 });
    }

    void perform_handshakes()
    {
        // Set the correct context for the browser-facing stream
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
                                                std::cerr << "[SESSION] ERROR 4a: Browser handshake FAILED: " << ec.message() << std::endl;
                                            }
                                        });

        // Set SNI for the server-facing stream
        if (!SSL_set_tlsext_host_name(server_stream_.native_handle(), host_.c_str()))
        {
            std::cerr << "[SESSION] ERROR: Failed to set SNI hostname." << std::endl;
            return;
        }
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
                                               std::cerr << "[SESSION] ERROR 4b: Target server handshake FAILED: " << ec.message() << std::endl;
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
        // Capture 'self' (the shared_ptr) to keep the session alive.
        auto self = shared_from_this();

        from.async_read_some(boost::asio::buffer(buffer),
                             [this, self, &from, &to, &buffer](const boost::system::error_code &ec, std::size_t bytes)
                             {
                                 if (!ec)
                                 {

                                     // Create a string from the received data
                                     std::string raw_data(buffer.data(), bytes);
                                     bool is_request = (&from == &browser_stream_);

                                     // Parse the data
                                     if (is_request && g_intercept_on)
                                     {
                                         paused_ = true;
                                         std::cout << "\n[!] REQUEST INTERCEPTED (ID: " << session_id_ << "). "
                                                   << "Type 'forward " << session_id_ << " <data>' or 'drop " << session_id_ << "'."
                                                   << std::endl;

                                         modified_data_ = raw_data; // Store original data
                                         std::cout << modified_data_ << std::endl;

                                         // Pause execution by waiting on the condition variable
                                         std::unique_lock<std::mutex> lock(mtx_);
                                         cv_.wait(lock, [this]
                                                  { return !paused_; }); // Blocks here until notified

                                         if (dropped_)
                                         {
                                             std::cout << "Dropping session " << session_id_ << std::endl;
                                             terminate(); // Close the connections
                                             return;      // Stop processing
                                         }

                                         // If not dropped, use the (potentially modified) data for the rest of the function
                                         raw_data = modified_data_;
                                         std::cout << raw_data << std::endl;
                                         bytes = raw_data.length();
                                     }
                                     ParsedHttpData parsed = parse_http_message(raw_data);

                                     if (is_request)
                                     {
                                         // This is a request, so save it and wait for the response.
                                         captured_request_ = parsed;
                                         captured_raw_request_ = raw_data;
                                     }
                                     else
                                     {
                                         // This is a response. We now have a complete pair. Log it.
                                         g_db_manager.log_transaction(captured_request_, captured_raw_request_, parsed, raw_data);
                                     }

                                     // Determine if it's a request or response and print it
                                     // A simple check: if the stream is from the browser, it's a request.
                                     std::string type = (&from == &browser_stream_) ? "REQUEST" : "RESPONSE";
                                     print_parsed_message(parsed, type);
                                     // Log the decrypted data
                                     async_write(to, boost::asio::buffer(buffer, bytes),
                                                 [this, self, &from, &to, &buffer](const boost::system::error_code &ec, std::size_t bytes)
                                                 {
                                                     if (!ec)
                                                     {
                                                         // Continue the relay loop
                                                         relay(from, to, buffer);
                                                     }
                                                 });
                                 }
                                 // Note: We don't continue the relay if there's an error (e.g., connection closed)
                             });
    }

    void terminate()
    {
        boost::system::error_code ec; // Ignored
        if (browser_stream_.lowest_layer().is_open())
        {
            browser_stream_.lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
            browser_stream_.lowest_layer().close(ec);
        }
        if (server_stream_.lowest_layer().is_open())
        {
            server_stream_.lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
            server_stream_.lowest_layer().close(ec);
        }
    }

    ssl::stream<tcp::socket> browser_stream_;
    ssl::stream<tcp::socket> server_stream_;
    boost::asio::streambuf request_buffer_;
    std::string host_, port_;
    int handshakes_done_ = 0;
    tcp::resolver resolver_;
    std::array<char, 8192> browser_to_server_buffer_;
    std::array<char, 8192> server_to_browser_buffer_;
    const uint64_t session_id_;
    std::mutex mtx_;
    std::condition_variable cv_;
    bool paused_ = false;
    bool dropped_ = false;
    std::string modified_data_;
    ParsedHttpData captured_request_;
    std::string captured_raw_request_;
    bool transaction_complete_ = false;
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
                    auto new_session = std::make_shared<session>(std::move(socket), client_ctx_);

                    // 2. NOW that it's a valid shared_ptr, add it to the global map
                    {
                        std::lock_guard<std::mutex> lock(g_sessions_mutex);
                        g_sessions[new_session->get_id()] = new_session; // get_id() is a new helper
                    }

                    // 3. Finally, start the session
                    new_session->start();
                }
                start_accept();
            });
    }
    tcp::acceptor acceptor_;
    ssl::context client_ctx_;
};

void command_line_interface()
{
    std::cout << "\n--- MITM Proxy CLI ---" << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  intercept on|off       - Enable/disable request interception" << std::endl;
    std::cout << "  list                   - List active sessions" << std::endl;
    std::cout << "  forward <id> <data>    - Forward intercepted request. Use \\r\\n for newlines." << std::endl;
    std::cout << "  drop <id>              - Drop intercepted request and close connection" << std::endl;
    std::cout << "  exit                   - Shutdown the proxy" << std::endl;
    std::cout << "----------------------" << std::endl;

    std::string line;
    while (std::cout << "> " && std::getline(std::cin, line) && line != "exit")
    {
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "intercept")
        {
            std::string state;
            iss >> state;
            if (state == "on")
            {
                g_intercept_on = true;
                std::cout << "Interception is now ON." << std::endl;
            }
            else if (state == "off")
            {
                g_intercept_on = false;
                std::cout << "Interception is now OFF." << std::endl;
            }
            else
            {
                std::cout << "Usage: intercept on|off" << std::endl;
            }
        }
        else if (cmd == "list")
        {
            std::lock_guard<std::mutex> lock(g_sessions_mutex);
            if (g_sessions.empty())
            {
                std::cout << "No active sessions." << std::endl;
            }
            else
            {
                std::cout << "Active session IDs: ";
                for (const auto &pair : g_sessions)
                {
                    if (!pair.second.expired())
                    { // Check if the session is still alive
                        std::cout << pair.first << " ";
                    }
                }
                std::cout << std::endl;
            }
        }
        else if (cmd == "forward")
        {
            uint64_t id;
            iss >> id;
            std::string data;
            if (!iss.eof())
            {
                std::getline(iss, data);
                data = data.substr(1); // Remove leading space
            }
            else
            {
                std::cout << "Error: Forward command requires data." << std::endl;
                continue;
            }

            // Replace literal "\r\n" with actual CRLF for convenience
            size_t pos = 0;
            while ((pos = data.find("\\r\\n", pos)) != std::string::npos)
            {
                data.replace(pos, 4, "\r\n");
            }

            std::cout << "sup" << std::endl;

            std::shared_ptr<session> s_ptr;
            {
                std::lock_guard<std::mutex> lock(g_sessions_mutex);
                auto it = g_sessions.find(id);
                if (it != g_sessions.end())
                {
                    s_ptr = it->second.lock(); // Upgrade weak_ptr to shared_ptr
                }
            }

            if (s_ptr)
            {
                s_ptr->forward(data);
            }
            else
            {
                std::cout << "Session " << id << " not found or has expired." << std::endl;
            }
        }
        else if (cmd == "drop")
        {
            uint64_t id;
            iss >> id;
            std::shared_ptr<session> s_ptr;
            {
                std::lock_guard<std::mutex> lock(g_sessions_mutex);
                auto it = g_sessions.find(id);
                if (it != g_sessions.end())
                {
                    s_ptr = it->second.lock();
                }
            }

            if (s_ptr)
            {
                s_ptr->drop();
            }
            else
            {
                std::cout << "Session " << id << " not found or has expired." << std::endl;
            }
        }
        else if (!cmd.empty())
        {
            std::cout << "Unknown command: " << cmd << std::endl;
        }
    }
    // A simple way to stop the server from the CLI
    std::cout << "Exiting..." << std::endl;
    std::exit(0);
}

int main(int argc, char *argv[])
{
    try
    {
        g_db_manager.initialize("history.db", "proxylab");
        CertificateManager::init_ca("rootCA.pem", "rootCA.key");
        std::thread cli_thread(command_line_interface);
        cli_thread.detach();

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
