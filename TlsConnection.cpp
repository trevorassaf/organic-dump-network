#include "TlsConnection.h"

#include <glog/logging.h>

#include <cassert>
#include <utility>

namespace network
{
TlsConnection::TlsConnection() : ssl_{nullptr} {
    LOG(ERROR) << "TlsConnection::TlsConnection() -- non-args ctor";
}

TlsConnection::TlsConnection(
  Fd fd,
  std::string peer_url,
  uint16_t peer_port,
  ssl_unique_ptr ssl)
: fd_{std::move(fd)},
  peer_url_{std::move(peer_url)},
  peer_port_{peer_port},
  ssl_{std::move(ssl)}
{
    LOG(ERROR) << "TlsConnection::TlsConnection() -- args ctor -- start";
    LOG(ERROR) << "TlsConnection::TlsConnection() -- args ctor -- end";
}

TlsConnection::~TlsConnection() {}

TlsConnection::TlsConnection(TlsConnection &&other)
{
    StealResources(&other);
}

TlsConnection &TlsConnection::operator=(TlsConnection &&other)
{
    if (this != &other)
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
  bool *out_eof,
  int *out_errno)
{
    LOG(ERROR) << "TlsConnection::Read() -- start";

    assert(data);
    assert(out_bytes_actually_read);
    assert(out_eof);
    assert(out_errno);

    int result = SSL_read(ssl_.get(), data, bytes_to_read);
    if (result < 0)
    {
        *out_bytes_actually_read = 0;
        *out_errno = errno;
        LOG(ERROR) << "TlsConnection::Read() -- SSL_read() failed";
        return false;
    }
    else if (result == 0)
    {
        LOG(ERROR) << "TlsConnection::Read() -- eof!";
        *out_eof = true;
        return true;
    }

    LOG(ERROR) << "TlsConnection::Read() -- after SSL_read()";

    *out_bytes_actually_read = result;

    LOG(ERROR) << "TlsConnection::Read() -- end. result: " << result;

    return true;
}

bool TlsConnection::Write(
    const uint8_t *data,
    size_t bytes_to_write,
    size_t *out_bytes_actually_written,
    bool *out_eof,
    int *out_errno)
{
    assert(data);
    assert(out_bytes_actually_written);
    assert(out_eof);
    assert(out_errno);

    LOG(ERROR) << "TlsConnection::Write() -- before SSL_write(). bytes to write: " << bytes_to_write
               << ". SSL fd: " << SSL_get_fd(ssl_.get());

    int result = SSL_write(ssl_.get(), data, bytes_to_write);
    if (result < 0)
    {
       *out_errno = errno;
       *out_bytes_actually_written = 0;
       return false; 
    }
    else if (result == 0)
    {
        *out_eof = true;
        return true;
    }

    *out_bytes_actually_written = result;
    return true;
}

void TlsConnection::StealResources(TlsConnection *other)
{
    assert(other);

    fd_ = std::move(other->fd_);
    peer_url_ = std::move(other->peer_url_);
    peer_port_ = other->peer_port_;
    other->peer_port_ = 0;
    ssl_ = std::move(other->ssl_);
}

} // namespace TlsConnection
