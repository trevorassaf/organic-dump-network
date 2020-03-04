#ifndef NETWORK_TLSCLIENT_H
#define NETWORK_TLSCLIENT_H

#include <cstdint>
#include <string>

#include  <openssl/bio.h>
#include  <openssl/ssl.h>
#include  <openssl/err.h>

#include "NetworkUtilities.h"
#include "TlsConnection.h"
#include "TlsUtilities.h"

namespace network
{

class TlsClient
{
public:
  TlsClient();
  TlsClient(
      std::string server_url,
      uint16_t server_port,
      ssl_ctx_unique_ptr ctx,
      WaitPolicy wait_policy);
  ~TlsClient();
  TlsClient(TlsClient &&other);
  TlsClient &operator=(TlsClient &&other);
  bool Connect(TlsConnection *out_connection);

private:
  void StealResources(TlsClient *other);

private:
  TlsClient(const TlsClient &other) = delete;
  TlsClient &operator=(const TlsClient &other);

private:
  std::string server_url_;
  uint16_t server_port_;
  ssl_ctx_unique_ptr ctx_;
  WaitPolicy wait_policy_;
};
} // namespace network

#endif // NETWORK_TLSCLIENT_H
