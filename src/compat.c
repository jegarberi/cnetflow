#ifdef COMPAT_CENTOS6
#define _GNU_SOURCE
#include <errno.h>
#include <sys/socket.h>

/*
 * Shim for sendmmsg which is missing in glibc < 2.14.
 * libuv may compile assuming it exists (if checked against headers),
 * but linking against older glibc fails.
 * We provide a dummy implementation to satisfy the linker.
 * libuv should handle the ENOSYS error if it attempts to call it.
 */
int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
  (void) sockfd;
  (void) msgvec;
  (void) vlen;
  (void) flags;
  errno = ENOSYS;
  return -1;
}
#endif
