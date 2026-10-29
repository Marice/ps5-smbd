/* libdcerpc includes <endian.h> (glibc); FreeBSD, and so the PS5, has the same functions in <sys/endian.h>. */
#pragma once
#if defined(__linux__)
#include_next <endian.h>
#else
#include <sys/endian.h>
#endif
