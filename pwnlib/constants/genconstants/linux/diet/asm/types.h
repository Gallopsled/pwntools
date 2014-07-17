#ifndef _ASM_TYPES_H
#define _ASM_TYPES_H

#include <sys/types.h>
#include <endian.h>

__BEGIN_DECLS

#ifdef __alpha__
typedef uint32_t umode_t;
#else
typedef uint16_t umode_t;
#endif

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
#if !defined(__STRICT_ANSI__) || __STDC_VERSION__ + 0 >= 199900L
typedef uint64_t __u64;
#endif

typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
#if !defined(__STRICT_ANSI__) || __STDC_VERSION__ + 0 >= 199900L
typedef int64_t __s64;
#endif

#if defined(__s390__) || (__WORDSIZE==64)
typedef unsigned long __kernel_size_t;
#else
typedef uint32_t __kernel_size_t;
#endif

#define __force
typedef uint16_t __le16;
typedef uint16_t __be16;
typedef uint32_t __le32;
typedef uint32_t __be32;
typedef uint64_t __le64;
typedef uint64_t __be64;

typedef uint16_t __sum16;
typedef uint32_t __wsum;

typedef uint16_t __kernel_sa_family_t;

__END_DECLS

#endif
