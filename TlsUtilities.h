#ifndef NETWORK_TLSUTILITIES_H
#define NETWORK_TLSUTILITIES_H

#include  <openssl/bio.h>
#include  <openssl/ssl.h>
#include  <openssl/err.h>

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>

namespace network
{
struct SslDeleter
{
void operator()(SSL *ssl)
{
   SSL_free(ssl); 
}
};

using ssl_unique_ptr = std::unique_ptr<SSL, SslDeleter>;

struct SslCtxDeleter
{
void operator()(SSL_CTX *ctx)
{
   SSL_CTX_free(ctx); 
}
};

using ssl_ctx_unique_ptr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

class TlsConnection;

bool SendTlsMessage(
    TlsConnection *cxn,
    const std::string &message);

bool ReadTlsMessage(
    TlsConnection *cxn,
    uint8_t *read_buffer,
    size_t length,
    std::string *out_message);

} // namespace network
#endif // NETWORK_TLSUTILITIES_H
