#ifndef	_ENDIAN_H
#define	_ENDIAN_H

#define	__LITTLE_ENDIAN	1234
#define	__BIG_ENDIAN	4321

#ifdef __mips__
#if _MIPS_SIM == _MIPS_SIM_ABI64
#define __mips64__
#else
#undef __mips64__
#endif
#endif

#if defined(__i386__) || defined(__x86_64__) || defined(__ia64__) || defined(__alpha__)
#define __BYTE_ORDER		__LITTLE_ENDIAN
#define __FLOAT_WORD_ORDER	__BYTE_ORDER
#endif

#if (defined(__mips__) && !defined(__MIPSEB)) || (defined(__arm__) && !defined(__ARMEB__)) || ((defined(__powerpc__) || defined(__sparc__)) && defined(__LITTLE_ENDIAN__))
#define __BYTE_ORDER		__LITTLE_ENDIAN
#define __FLOAT_WORD_ORDER	__BYTE_ORDER
#endif

/* rest is big endian */

#ifndef __BYTE_ORDER
#define __BYTE_ORDER		__BIG_ENDIAN
#define __FLOAT_WORD_ORDER	__BYTE_ORDER
#endif

#define LITTLE_ENDIAN		__LITTLE_ENDIAN
#define BIG_ENDIAN		__BIG_ENDIAN
#define BYTE_ORDER		__BYTE_ORDER

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define __LONG_LONG_PAIR(HI, LO) LO, HI
#elif __BYTE_ORDER == __BIG_ENDIAN
# define __LONG_LONG_PAIR(HI, LO) HI, LO
#endif

#if defined(__alpha__) || defined(__mips64__) || defined(__sparc_v9__) || defined(__x86_64__) || defined(__ia64__) || defined(__powerpc64__) || defined(__s390x__)
#define __WORDSIZE 64
#endif

#if defined(__x86_64__) || defined(__powerpc64__) || defined(__sparc_v9__)
#define __WORDSIZE_COMPAT32 1
#endif

#if defined(__sparc__) && (__arch64__)
#define __WORDSIZE 64
#endif

#ifndef __WORDSIZE
#define __WORDSIZE 32
#endif

#endif
