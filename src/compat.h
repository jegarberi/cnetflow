#ifndef CNETFLOW_COMPAT_H
#define CNETFLOW_COMPAT_H

#include <stddef.h>

#if defined(__has_include)
# if __has_include(<features.h>)
#  include <features.h>
# endif
#endif

#ifndef __GLIBC_PREREQ
# if defined(__GLIBC__) && defined(__GLIBC_MINOR__)
#  define __GLIBC_PREREQ(maj, min) \
	((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
# else
#  define __GLIBC_PREREQ(maj, min) 0
# endif
#endif

#if defined(COMPAT_CENTOS6) || !defined(__GLIBC__) || !__GLIBC_PREREQ(2, 38)
size_t strlcpy(char *dst, const char *src, size_t dsize);
#endif

#endif // CNETFLOW_COMPAT_H
