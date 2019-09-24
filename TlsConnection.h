#ifndef NETWORK_TLSCONNECTION_H
#define NETWORK_TLSCONNECTION_H

#include <cstdint>
#include <memory>
#include <string>

#include  <openssl/bio.h>
#include  <openssl/ssl.h>
#include  <openssl/err.h>

#include "Fd.h"
#include "TlsUtilities.h"

namespace network
{

class TlsConnection
{
public:
  TlsConnection();
  TlsConnection(
      Fd fd,
      std::string peer_url,
      uint16_t peer_port,
      ssl_unique_ptr ssl);
  ~TlsConnection();
  TlsConnection(TlsConnection &&other);
  TlsConnection &operator=(TlsConnection &&other);

  const Fd &GetFd() const;
  bool Read(
      uint8_t *data,
      size_t bytes_to_read,
      size_t *out_bytes_actually_read,
      int *out_errno);
  bool Write(
      const uint8_t *data,
      size_t bytes_to_write,
      size_t *out_bytes_actually_written,
      int *out_errno);

private:
  void StealResources(TlsConnection *other);

private:
  TlsConnection(const TlsConnection &other) = delete;
  TlsConnection &operator=(const TlsConnection &other);

private:
  Fd fd_;
  std::string peer_url_;
  uint16_t peer_port_;
  ssl_unique_ptr ssl_;
};
} // namespace network

#endif // NETWORK_TLSCONNECTION_H
