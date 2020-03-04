#include "TlsClientFactory.h"

#include  <openssl/bio.h>
#include  <openssl/ssl.h>
#include  <openssl/err.h>

#include <glog/logging.h>

#include <cassert>

#include "TlsUtilities.h"

namespace network
{
bool TlsClientFactory::Create(
    std::string server_url,
    uint16_t server_port,
    std::string client_cert,
    std::string client_key,
    std::string ca_cert,
    WaitPolicy wait_policy,
    TlsClient *out_client)
{
    assert(out_client);

    const SSL_METHOD *method = TLSv1_2_client_method();
    ssl_ctx_unique_ptr ctx{SSL_CTX_new(method)};

    if (ctx.get() == nullptr)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_load_verify_locations(ctx.get(), ca_cert.c_str(), nullptr) != 1)
    {
        LOG(ERROR) << "Failed to load client CA file: " << ca_cert;
        return false;
    }

    if (SSL_CTX_use_certificate_file(ctx.get(), client_cert.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        LOG(ERROR) << "Failed to load client cert " << client_cert;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx.get(), client_key.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        LOG(ERROR) << "Failed to load private key: " << client_key;
        return false;
    }


    if (SSL_CTX_check_private_key(ctx.get()) != 1)
    {
        LOG(ERROR) << "Private key does not agree with cert";
        return false;
    }

    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(ctx.get(), 1);

    *out_client = TlsClient{
        std::move(server_url),
        server_port,
        std::move(ctx),
        wait_policy};

    return true;
}
} // namespace network
