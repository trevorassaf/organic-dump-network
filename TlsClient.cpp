#include "TlsClient.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#include <cassert>
#include <cstdio>

#include <glog/logging.h>

namespace network
{
TlsClient::TlsClient() : ctx_{nullptr} {}

TlsClient::TlsClient(
    std::string server_url,
    uint16_t server_port,
    ssl_ctx_unique_ptr ctx,
    WaitPolicy wait_policy)
  : server_url_{std::move(server_url)},
    server_port_{server_port},
    ctx_{std::move(ctx)},
    wait_policy_{wait_policy} {}

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

    ssl_unique_ptr ssl{SSL_new(ctx_.get())};
    SSL_set_fd(ssl.get(), fd_wrapper.Get());

    if (SSL_connect(ssl.get()) != 1)
    {
        LOG(ERROR) << "Failed to perform SSL handshake";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (wait_policy_ == WaitPolicy::NON_BLOCKING && !SetNonBlocking(fd_wrapper.Get())) {
      LOG(ERROR) << "Failed to configure non-blocking server socket";
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
    ctx_ = std::move(other->ctx_);
    wait_policy_ = other->wait_policy_;
}

} // namespace network
