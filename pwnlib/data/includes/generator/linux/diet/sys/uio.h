#ifndef _SYS_UIO
#define _SYS_UIO 1

#include <sys/socket.h>

__BEGIN_DECLS

struct iovec {
  void* iov_base;	/* BSD uses caddr_t (1003.1g requires void *) */
  size_t iov_len;	/* Must be size_t (1003.1g) */
};

/* I have no idea why susv3 specifies count as int instead of size_t */
ssize_t readv(int filedes, const struct iovec *vector, int count) __THROW;
ssize_t writev(int filedes, const struct iovec *vector, int count) __THROW;

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset) __THROW;
ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset) __THROW;

__END_DECLS

#endif
