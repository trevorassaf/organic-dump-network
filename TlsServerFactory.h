#ifndef NETWORK_TLSSERVERFACTORY_H
#define NETWORK_TLSSERVERFACTORY_H

#include <cstdint>
#include <string>

#include "NetworkUtilities.h"
#include "TlsServer.h"

namespace network
{

class TlsServerFactory
{
public:
  bool Create(
      std::string server_cert,
      std::string server_key,
      std::string ca_cert,
      uint16_t port,
      WaitPolicy policy,
      TlsServer *out_server);
};
} // namespace network

#endif // NETWORK_TLSSERVERFACTORY_H
