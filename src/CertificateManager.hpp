#ifndef CERTIFICATE_MANAGER_HPP
#define CERTIFICATE_MANAGER_HPP

#include <string>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <boost/asio/ssl/context.hpp>

// --- START: CHANGED SECTION ---

// Instead of forward-declaring, include the actual OpenSSL headers.
// This ensures we always use the one true definition of these types.
#include <openssl/x509.h>
#include <openssl/evp.h>

// --- END: CHANGED SECTION ---


class CertificateManager {
public:
    static void init_ca(const std::string& ca_cert_path, const std::string& ca_key_path);
    static boost::asio::ssl::context& get_server_context(const std::string& hostname);

private:
    struct SslContextData {
        boost::asio::ssl::context context;
        std::shared_ptr<EVP_PKEY> key;
        std::shared_ptr<X509> cert;

        SslContextData(boost::asio::ssl::context&& ctx, std::shared_ptr<EVP_PKEY> k, std::shared_ptr<X509> c);
    };

    static std::shared_ptr<X509> ca_cert_;
    static std::shared_ptr<EVP_PKEY> ca_key_;
    static std::mutex mtx_;

    static std::unordered_map<std::string, SslContextData> context_cache_;

    // OpenSSL helpers
    static std::shared_ptr<EVP_PKEY> create_key();
    static std::shared_ptr<X509> create_signed_certificate(const std::string& hostname, EVP_PKEY* server_key);
};

#endif // CERTIFICATE_MANAGER_HPP