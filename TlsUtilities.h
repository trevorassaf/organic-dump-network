#ifndef NETWORK_TLSUTILITIES_H
#define NETWORK_TLSUTILITIES_H

#include  <openssl/bio.h>
#include  <openssl/ssl.h>
#include  <openssl/err.h>

#include <glog/logging.h>

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
   LOG(ERROR) << "SSL::~SSL()";
   if (ssl)
   {
       LOG(ERROR) << "ssl is not nullptr";
       SSL_free(ssl); 
   }
   else
   {
      LOG(ERROR) << "ssl is nullptr";
   }
}
};

using ssl_unique_ptr = std::unique_ptr<SSL, SslDeleter>;

struct SslCtxDeleter
{
void operator()(SSL_CTX *ctx)
{
   LOG(ERROR) << "SSL_CTX::~SSL_CTX()";
   if (ctx)
   {
       LOG(ERROR) << "ssl ctx is not nullptr";
       SSL_CTX_free(ctx); 
   }
   else
   {
      LOG(ERROR) << "ssl ctx is nullptr";
   }
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
