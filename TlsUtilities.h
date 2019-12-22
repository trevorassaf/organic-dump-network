#ifndef NETWORK_TLSUTILITIES_H
#define NETWORK_TLSUTILITIES_H

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>

#include  <openssl/bio.h>
#include  <openssl/ssl.h>
#include  <openssl/err.h>

#include <glog/logging.h>

#include <google/protobuf/message.h>

namespace network
{

void InitOpenSslForProcess();

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

bool SendTlsProtobufMessage(
    TlsConnection *cxn,
    uint8_t msg_type,
    google::protobuf::Message *msg,
    bool *out_cxn_closed);

bool SendTlsData(
    TlsConnection *cxn,
    const uint8_t *data,
    size_t data_len);

bool ReadTlsData(
    TlsConnection *cxn,
    uint8_t *data,
    size_t data_len);

bool ReadTlsProtobufMessageHeader(
    TlsConnection *cxn,
    uint8_t *out_type,
    uint32_t *out_size);

} // namespace network
#endif // NETWORK_TLSUTILITIES_H
