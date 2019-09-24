#ifndef NETWORK_TLSSERVER_H
#define NETWORK_TLSSERVER_H

#include  <openssl/bio.h>
#include  <openssl/ssl.h>
#include  <openssl/err.h>

#include "Fd.h"
#include "TlsConnection.h"
#include "TlsUtilities.h"

namespace network
{

class TlsServer
{
public:
  TlsServer();
  TlsServer(
      ssl_ctx_unique_ptr ctx,
      Fd fd);
  ~TlsServer();
  TlsServer(TlsServer &&other);
  TlsServer &operator=(TlsServer &&other);

  const Fd &GetFd() const;
  bool Accept(TlsConnection *out_connection);

private:
  void StealResources(TlsServer *other);

private:
  TlsServer(const TlsServer &other) = delete;
  TlsServer &operator=(const TlsServer &other);

private:
  ssl_ctx_unique_ptr ctx_;
  Fd fd_;
};
} // namespace network

#endif // NETWORK_TLSSERVER_H
