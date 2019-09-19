#include "Fd.h"

#include <unistd.h>

#include <cassert>

namespace network
{

namespace
{
constexpr int INVALID_FD = -1;
} // namespace

Fd::Fd() : fd_{INVALID_FD} {}

Fd::Fd(int fd) : fd_{fd} {}

Fd::~Fd()
{
    Close(&fd_);
}

Fd::Fd(Fd &&other)
{
    StealResources(&other);
}

Fd &Fd::operator=(Fd &&other)
{
    if (this != &other)
    {
        Close(&fd_);
        StealResources(&other);
    }
    return *this;
}

int Fd::Get() const
{
    return fd_;
}

void Fd::StealResources(Fd *other)
{
    assert(other);

    fd_ = other->fd_;
    other->fd_ = INVALID_FD;
}

void Fd::Close(int *fd)
{
    assert(fd);

    if (*fd == INVALID_FD)
    {
        return;
    }

    close(*fd);
}

} // namespace network
