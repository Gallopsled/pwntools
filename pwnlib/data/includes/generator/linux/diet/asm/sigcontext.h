#ifndef _ASM_SIGCONTEXT_H
#define _ASM_SIGCONTEXT_H

#include <sys/cdefs.h>

__BEGIN_DECLS

#if defined(__i386__)
#include <asm/i386-sigcontext.h>
#endif

#if defined(__x86_64__)
#include <asm/x86_64-sigcontext.h>
#endif

#ifdef __sparc__
#include <asm/sparc-sigcontext.h>
#endif

#ifdef __mips__
#include <asm/mips-sigcontext.h>
#endif

#if defined(__powerpc__) || defined(__powerpc64__)
#include <asm/ppc-sigcontext.h>
#endif

#ifdef __alpha__
#include <asm/alpha-sigcontext.h>
#endif

#ifdef __arm__
#include <asm/arm-sigcontext.h>
#endif

#ifdef __hppa__
#include <asm/parisc-sigcontext.h>
#endif

#ifdef __ia64__
#include <asm/ia64-sigcontext.h>
#endif

#ifdef __s390__
#include <asm/s390-sigcontext.h>
#endif

__END_DECLS

#endif
