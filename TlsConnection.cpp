#include "TlsConnection.h"

#include <glog/logging.h>

#include <cassert>
#include <utility>

namespace network
{
TlsConnection::TlsConnection() {}

TlsConnection::TlsConnection(
  Fd fd,
  std::string server_url,
  uint16_t server_port,
  ssl_unique_ptr ssl)
: fd_{std::move(fd)},
  server_url_{std::move(server_url)},
  server_port_{server_port},
  ssl_{std::move(ssl)}
{}

TlsConnection::~TlsConnection() {}

TlsConnection::TlsConnection(TlsConnection &&other)
{
    StealResources(&other);
}

TlsConnection &TlsConnection::operator=(TlsConnection &&other)
{
    if (this == &other)
    {
        StealResources(&other);
    }

    return *this;
}

const Fd &TlsConnection::GetFd() const
{
    return fd_;
}

bool TlsConnection::Read(
  uint8_t *data,
  size_t bytes_to_read,
  size_t *out_bytes_actually_read,
  int *out_errno)
{
    assert(data);
    assert(out_bytes_actually_read);
    assert(out_errno);

    int result = SSL_read(ssl_.get(), data, bytes_to_read);
    if (result < 0)
    {
        *out_bytes_actually_read = 0;
        *out_errno = errno;
        return false;
    }

    *out_bytes_actually_read = result;
    return true;
}

bool TlsConnection::Write(
    const uint8_t *data,
    size_t bytes_to_write,
    size_t *out_bytes_actually_written,
    int *out_errno)
{
    assert(data);
    assert(out_bytes_actually_written);
    assert(out_errno);

    int result = SSL_write(ssl_.get(), data, bytes_to_write);
    if (result < 0)
    {
       *out_errno = errno;
       *out_bytes_actually_written = 0;
       return false; 
    }

    *out_bytes_actually_written = result;
    return true;
}

void TlsConnection::StealResources(TlsConnection *other)
{
    assert(other);

    fd_ = std::move(other->fd_);
    server_url_ = std::move(other->server_url_);
    server_port_ = other->server_port_;
    other->server_port_ = 0;
    ssl_ = std::move(other->ssl_);
}

} // namespace TlsConnection
