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
   if (ssl)
   {
       SSL_free(ssl); 
   }
}
};

using ssl_unique_ptr = std::unique_ptr<SSL, SslDeleter>;

struct SslCtxDeleter
{
void operator()(SSL_CTX *ctx)
{
   if (ctx)
   {
       SSL_CTX_free(ctx); 
   }
}
};

using ssl_ctx_unique_ptr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

class TlsConnection;

bool SendTlsMessage(
    TlsConnection *cxn,
    const std::string &message,
    bool *out_cxn_closed=nullptr);

bool ReadTlsMessage(
    TlsConnection *cxn,
    uint8_t *read_buffer,
    size_t length,
    std::string *out_message,
    bool *out_cxn_closed=nullptr);

bool SendTlsProtobufMessage(
    TlsConnection *cxn,
    uint8_t msg_type,
    google::protobuf::Message *msg,
    bool *out_cxn_closed=nullptr);

bool SendTlsData(
    TlsConnection *cxn,
    const uint8_t *data,
    size_t data_len,
    bool *out_cxn_closed=nullptr);

bool ReadTlsData(
    TlsConnection *cxn,
    uint8_t *data,
    size_t data_len,
    bool *out_cxn_closed=nullptr);

struct ProtobufMessageHeader {
    uint8_t type;
    uint32_t size;
};

bool ReadTlsProtobufMessageHeader(
    TlsConnection *cxn,
    ProtobufMessageHeader *out_header,
    bool *out_cxn_closed=nullptr);

template <typename TMessage>
bool ReadTlsProtobufMessageBody(
    TlsConnection *cxn,
    uint8_t *tmp_buffer,
    size_t msg_len,
    TMessage *out_message,
    bool *out_cxn_closed=nullptr)
{
    assert(cxn);
    assert(tmp_buffer);
    assert(out_message);

    if (!ReadTlsData(cxn, tmp_buffer, msg_len, out_cxn_closed))
    {
        LOG(ERROR) << "Failed to read TLS data";
        return false;
    }

    std::string msg_str{reinterpret_cast<char *>(tmp_buffer), msg_len};
    out_message->ParseFromString(msg_str);
    return true;
}

} // namespace network
#endif // NETWORK_TLSUTILITIES_H
