#include "NetworkUtilities.h"

#include <fcntl.h>
#include <unistd.h>

namespace network
{

bool SetNonBlocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0;
}

} // namespace network
