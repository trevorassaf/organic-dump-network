#include "TlsServer.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#include  <openssl/bio.h>
#include  <openssl/ssl.h>
#include  <openssl/err.h>

#include <glog/logging.h>

#include <cassert>
#include <cstdint>

namespace network
{

TlsServer::TlsServer() : ctx_{nullptr}, fd_{} {}

TlsServer::TlsServer(
    ssl_ctx_unique_ptr ctx,
    Fd fd)
  : ctx_{std::move(ctx)},
    fd_{std::move(fd)}
{}

TlsServer::~TlsServer() {}

TlsServer::TlsServer(TlsServer &&other)
{
    StealResources(&other);
}

TlsServer &TlsServer::operator=(TlsServer &&other)
{
    if (this != &other)
    {
        StealResources(&other);
    }
    return *this;
}

const Fd &TlsServer::GetFd() const
{
    return fd_;
}

bool TlsServer::Accept(TlsConnection *out_connection)
{
    assert(out_connection);

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int result = accept(
        fd_.Get(),
        reinterpret_cast<struct sockaddr *>(&client_addr),
        &addr_len);

    if (result < 0)
    {
        LOG(ERROR) << "Failed to accept connection: " << strerror(errno);
        return false;
    }

    Fd connection_fd{result};
    char client_ipv4_string[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ipv4_string, INET_ADDRSTRLEN);
    std::string client_ipv4{client_ipv4_string};

    ssl_unique_ptr ssl{SSL_new(ctx_.get())};

    if (ssl.get() == nullptr)
    {
        LOG(ERROR) << "Failed to initialize SSL connection";
        return false;
    }

    SSL_set_fd(ssl.get(), connection_fd.Get());

    if (SSL_accept(ssl.get()) != 1)
    {
        LOG(ERROR) << "Failed to conduct SSL handshake";
        ERR_print_errors_fp(stderr);
        return false;
    }
    fcntl(result, F_SETFL, O_NONBLOCK);

    *out_connection = TlsConnection{
        std::move(connection_fd),
        std::move(client_ipv4_string),
        ntohs(client_addr.sin_port),
        std::move(ssl)};

    return true;
}

void TlsServer::StealResources(TlsServer *other)
{
    ctx_ = std::move(other->ctx_);
    fd_ = std::move(other->fd_);
}
} // namespace network
