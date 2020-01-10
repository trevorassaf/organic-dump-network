#include "TlsServerFactory.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#include <cassert>
#include <cstdint>

#include  <openssl/bio.h>
#include  <openssl/ssl.h>
#include  <openssl/err.h>

#include <glog/logging.h>

#include "NetworkUtilities.h"

namespace
{
constexpr size_t CONNECTION_QUEUE_SIZE = 10;
} // namespace

namespace network
{
bool TlsServerFactory::Create(
    std::string server_cert,
    std::string server_key,
    std::string ca_cert,
    uint16_t port,
    WaitPolicy policy,
    TlsServer *out_server)
{
    assert(out_server);

    const SSL_METHOD *method = TLSv1_2_server_method();
    ssl_ctx_unique_ptr ctx{SSL_CTX_new(method)};

    if (ctx.get() == nullptr)
    {
        LOG(ERROR) << "Failed to initialize ctx";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_load_verify_locations(ctx.get(), ca_cert.c_str(), nullptr) != 1)
    {
        LOG(ERROR) << "Failed to load verify locations for ca cert: " << ca_cert;
        return false;
    }

    SSL_CTX_set_client_CA_list(ctx.get(), SSL_load_client_CA_file(ca_cert.c_str()));

    if (SSL_CTX_use_certificate_file(ctx.get(), server_cert.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        LOG(ERROR) << "Failed to load server certificate file: " << server_cert;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx.get(), server_key.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        LOG(ERROR) << "Failed to load private key: " << server_key;
        return false;
    }

    // Ensure cert and private key agree with one another
    if (SSL_CTX_check_private_key(ctx.get()) != 1)
    {
        LOG(ERROR) << "Private key does not match public key";
        return false;
    }

    // Require mutual authentication. Only accept peer certs signed by CA directly.
    SSL_CTX_set_verify(
        ctx.get(),
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        nullptr);

    // Accept only certs signed by CA itself. No cert chaining.
    SSL_CTX_set_verify_depth(ctx.get(), 1);

    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        LOG(ERROR) << "Failed to initialize socket";
        return false;
    }

    Fd server_fd{fd};

    if (policy == WaitPolicy::NON_BLOCKING && !SetNonBlocking(fd)) {
      LOG(ERROR) << "Failed to configure non-blocking server socket";
      return false;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(
            server_fd.Get(),
            reinterpret_cast<sockaddr *>(&addr),
            sizeof(addr)) < 0)
    {
        LOG(ERROR) << "Failed to bind socket: " << strerror(errno);
        return false;
    }

    if (listen(
          server_fd.Get(),
          CONNECTION_QUEUE_SIZE) < 0)
    {
        LOG(ERROR) << "Failed to configure socket in listening mode";
        return false;
    }

    *out_server = TlsServer{std::move(ctx), std::move(server_fd)};
    return true;
}
} // namespace network
