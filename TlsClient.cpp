#include "TlsClient.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#include <cassert>

#include <glog/logging.h>

namespace network
{
TlsClient::TlsClient() {}

TlsClient::TlsClient(
    std::string server_url,
    uint16_t server_port,
    ssl_ctx_unique_ptr ssl_ctx)
  : server_url_{std::move(server_url)},
    server_port_{server_port},
    ssl_ctx_{std::move(ssl_ctx)}
{}

TlsClient::~TlsClient() {}

TlsClient::TlsClient(TlsClient &&other)
{
    StealResources(&other);
}

TlsClient &TlsClient::operator=(TlsClient &&other)
{
    if (this != &other)
    {
        StealResources(&other);
    }

    return *this;
}

bool TlsClient::Connect(TlsConnection *out_connection)
{
    assert(out_connection);

    // Initialize  TLS connection
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    inet_pton(AF_INET, server_url_.c_str(), &(addr.sin_addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port_);

    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        LOG(ERROR) << "Failed to initialize socket";
        return false;
    }

    Fd fd_wrapper{fd};
    if (connect(
          fd_wrapper.Get(),
          reinterpret_cast<struct sockaddr*>(&addr),
          sizeof(addr)) < 0)
    {
        LOG(ERROR) << "Failed to connect server";
        return false;
    }

    ssl_unique_ptr ssl{SSL_new(ssl_ctx_.get())};
    SSL_set_fd(ssl.get(), fd_wrapper.Get());

    if (SSL_connect(ssl.get()) != 1)
    {
        LOG(ERROR) << "Failed to perform SSL handshake";
        ERR_print_errors_fp(stderr);
        return false;
    }

    *out_connection = TlsConnection{
      std::move(fd_wrapper),
      server_url_,
      server_port_,
      std::move(ssl)};

    return true;
}

void TlsClient::StealResources(TlsClient *other)
{
    assert(other);

    server_url_ = std::move(other->server_url_);
    server_port_ = other->server_port_;
    other->server_port_ = 0;
    ssl_ctx_ = std::move(other->ssl_ctx_);
}

} // namespace network
