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
      uint16_t port,
      std::string server_cert,
      std::string server_key,
      std::string ca_cert,
      WaitPolicy wait_policy,
      TlsServer *out_server);
};
} // namespace network

#endif // NETWORK_TLSSERVERFACTORY_H
