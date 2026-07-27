#ifndef CNETFLOW_COMPAT_H
#define CNETFLOW_COMPAT_H

#include <stddef.h>
#include <features.h>

#if defined(COMPAT_CENTOS6) || !defined(__GLIBC__) || (defined(__GLIBC__) && !__GLIBC_PREREQ(2, 38))
size_t strlcpy(char *dst, const char *src, size_t dsize);
#endif

#endif // CNETFLOW_COMPAT_H
