#ifndef NETWORK_FD_H
#define NETWORK_FD_H

namespace network
{
class Fd
{
public:
  Fd();
  Fd(int fd);
  ~Fd();
  Fd(Fd &&other);
  Fd &operator=(Fd &&other);
  int Get() const;

private:
  Fd(const Fd &other) = delete;
  Fd &operator=(const Fd &other);

private:
  void StealResources(Fd *other);
  void Close(int *fd);

private:
  int fd_;
};
} // namespace network

#endif // NETWORK_FD_H
