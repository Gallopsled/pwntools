#ifndef _STDDEF_H
#define _STDDEF_H

#include <sys/cdefs.h>

__BEGIN_DECLS

/* ugh.  This is normally provided by gcc. */

#ifdef __GNUC__
typedef __PTRDIFF_TYPE__ ptrdiff_t;
typedef __SIZE_TYPE__ size_t;
#if !defined(__cplusplus)
typedef __WCHAR_TYPE__ wchar_t;
#endif
#else
typedef signed long ptrdiff_t;
typedef unsigned long size_t;
typedef int wchar_t;
#endif

#undef NULL
#if defined(__cplusplus)
#define NULL 0
#else
#define NULL (void*)0
#endif

#undef offsetof
#define offsetof(type,member) ((size_t) &((type*)0)->member)

__END_DECLS

#endif
