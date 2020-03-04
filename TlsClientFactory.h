#ifndef NETWORK_TLSCLIENTFACTORY_H
#define NETWORK_TLSCLIENTFACTORY_H

#include "NetworkUtilities.h"
#include "TlsClient.h"
#include "TlsUtilities.h"

namespace network
{

class TlsClientFactory
{
public:
  bool Create(
      std::string server_url,
      uint16_t server_port,
      std::string client_cert,
      std::string client_key,
      std::string ca_cert,
      WaitPolicy wait_policy,
      TlsClient *out_client);
};

} // namespace network

#endif // NETWORK_TLSCLIENTFACTORY_H
