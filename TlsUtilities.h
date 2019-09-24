#ifndef NETWORK_TLSUTILITIES_H
#define NETWORK_TLSUTILITIES_H
namespace network
{
struct SslDeleter
{
void operator()(SSL *ssl)
{
   SSL_free(ssl); 
}
};

using ssl_unique_ptr = std::unique_ptr<SSL, SslDeleter>;

struct SslCtxDeleter
{
void operator()(SSL_CTX *ctx)
{
   SSL_CTX_free(ctx); 
}
};

using ssl_ctx_unique_ptr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

} // namespace network
#endif // NETWORK_TLSUTILITIES_H
