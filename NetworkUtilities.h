#ifndef NETWORK_NETWORKUTILITIES_H
#define NETWORK_NETWORKUTILITIES_H

#include <cstdint>

namespace network
{

enum class WaitPolicy : uint8_t {
  BLOCKING,
  NON_BLOCKING,
};

bool SetNonBlocking(int fd);

} // namespace network
#endif // NETWORK_NETWORKUTILITIES_H
