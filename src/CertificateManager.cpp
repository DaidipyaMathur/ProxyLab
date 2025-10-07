#include "CertificateManager.hpp"
#include <fstream>
#include <stdexcept>

// Required OpenSSL headers
#include <openssl/pem.h>      // For PEM_read_*, PEM_write_*
#include <openssl/x509.h>     // For X509_* functions
#include <openssl/x509v3.h>   // For X509V3_* extensions
#include <openssl/evp.h>      // For EVP_PKEY_* functions
#include <openssl/rsa.h>      // For RSA_* functions
#include <openssl/bn.h>       // For BIGNUM
#include <openssl/ssl.h>      // For SSL_CTX_* functions

// Initialize static members
std::shared_ptr<X509> CertificateManager::ca_cert_ = nullptr;
std::shared_ptr<EVP_PKEY> CertificateManager::ca_key_ = nullptr;
std::mutex CertificateManager::mtx_;
// Add this missing constructor definition to CertificateManager.cpp
CertificateManager::SslContextData::SslContextData(boost::asio::ssl::context&& ctx, std::shared_ptr<EVP_PKEY> k, std::shared_ptr<X509> c)
    : context(std::move(ctx)), key(std::move(k)), cert(std::move(c)) {}

// --- START: CHANGED SECTION ---

// 2. Change the cache to store our new struct
std::unordered_map<std::string, CertificateManager::SslContextData> CertificateManager::context_cache_;

// --- END: CHANGED SECTION ---


void CertificateManager::init_ca(const std::string& ca_cert_path, const std::string& ca_key_path) {
    FILE* fp_cert = fopen(ca_cert_path.c_str(), "r");
    if (!fp_cert) throw std::runtime_error("Failed to open CA certificate file: " + ca_cert_path);
    X509* raw_cert = PEM_read_X509(fp_cert, NULL, NULL, NULL);
    fclose(fp_cert);
    if (!raw_cert) throw std::runtime_error("Failed to read CA certificate");
    ca_cert_ = std::shared_ptr<X509>(raw_cert, X509_free);

    FILE* fp_key = fopen(ca_key_path.c_str(), "r");
    if (!fp_key) throw std::runtime_error("Failed to open CA key file: " + ca_key_path);
    EVP_PKEY* raw_key = PEM_read_PrivateKey(fp_key, NULL, NULL, NULL);
    fclose(fp_key);
    if (!raw_key) throw std::runtime_error("Failed to read CA key");
    ca_key_ = std::shared_ptr<EVP_PKEY>(raw_key, EVP_PKEY_free);
}

boost::asio::ssl::context& CertificateManager::get_server_context(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(mtx_);

    // Check the cache
    if (context_cache_.count(hostname)) {
        return context_cache_.at(hostname).context;
    }

    // --- START: CHANGED SECTION (Logic for creating and storing) ---

    // Create the key and certificate
    auto server_key = create_key();
    auto server_cert = create_signed_certificate(hostname, server_key.get());

    // Create and configure the SSL context
    boost::asio::ssl::context temp_ctx(boost::asio::ssl::context::tls_server);
    temp_ctx.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::single_dh_use);

    // Use the raw pointers from our smart pointers
    // These pointers are now safe because the smart pointers will be stored in the cache
    SSL_CTX_use_PrivateKey(temp_ctx.native_handle(), server_key.get());
    SSL_CTX_use_certificate(temp_ctx.native_handle(), server_cert.get());

    // 3. Create our struct and emplace it into the cache
    auto [it, success] = context_cache_.emplace(
        hostname,
        SslContextData(std::move(temp_ctx), server_key, server_cert)
    );

    // Return a reference to the context within the newly cached struct
    return it->second.context;

    // --- END: CHANGED SECTION ---
}

// This is the new, modern version of create_key()
std::shared_ptr<EVP_PKEY> CertificateManager::create_key() {
    EVP_PKEY* raw_pkey = nullptr;
    
    // Create a context for the key generation
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL), 
        EVP_PKEY_CTX_free
    );

    if (!pctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX");

    // Initialize the key generation
    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        throw std::runtime_error("Failed to initialize keygen");
    }

    // Set the RSA key length
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx.get(), 2048) <= 0) {
        throw std::runtime_error("Failed to set RSA keygen bits");
    }

    // Generate the key
    if (EVP_PKEY_generate(pctx.get(), &raw_pkey) <= 0) {
        throw std::runtime_error("Failed to generate EVP_PKEY");
    }

    return std::shared_ptr<EVP_PKEY>(raw_pkey, EVP_PKEY_free);
}

// Helper to add X509 extensions
void add_ext(X509 *cert, int nid, const char *value) {
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex) {
        throw std::runtime_error("Failed to create X509V3 extension");
    }
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
}

std::shared_ptr<X509> CertificateManager::create_signed_certificate(const std::string& hostname, EVP_PKEY* server_key) {
    X509* raw_cert = X509_new();
    if (!raw_cert) throw std::runtime_error("Failed to create X509 certificate");

    X509_set_version(raw_cert, 2);

    // Set a unique serial number (using time is okay for this purpose)
    ASN1_INTEGER_set(X509_get_serialNumber(raw_cert), static_cast<long>(time(NULL)));

    X509_gmtime_adj(X509_getm_notBefore(raw_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(raw_cert), 31536000L); // 1 year
    X509_set_pubkey(raw_cert, server_key);

    X509_NAME *name = X509_get_subject_name(raw_cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)hostname.c_str(), -1, -1, 0);

    // The issuer is our CA
    X509_set_issuer_name(raw_cert, X509_get_subject_name(ca_cert_.get()));
    
    // Add required extensions
    add_ext(raw_cert, NID_basic_constraints, "CA:FALSE");
    add_ext(raw_cert, NID_key_usage, "digitalSignature,keyEncipherment");
    std::string san = "DNS:" + hostname;
    add_ext(raw_cert, NID_subject_alt_name, san.c_str());

    // Sign the certificate with our CA's private key
    if (X509_sign(raw_cert, ca_key_.get(), EVP_sha256()) == 0) {
        X509_free(raw_cert);
        throw std::runtime_error("Failed to sign certificate");
    }

    return std::shared_ptr<X509>(raw_cert, X509_free);
}