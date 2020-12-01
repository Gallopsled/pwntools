#ifndef _SYS_MMAN_H
#define _SYS_MMAN_H

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/stat.h>

__BEGIN_DECLS

#define MREMAP_MAYMOVE	1UL
#define MREMAP_FIXED	2UL

#define PROT_READ	0x1		/* page can be read */
#define PROT_WRITE	0x2		/* page can be written */
#define PROT_EXEC	0x4		/* page can be executed */
#define PROT_SEM	0x8		/* page may be used for atomic ops */
#define PROT_NONE	0x0		/* page can not be accessed */

#define PROT_GROWSDOWN	0x01000000	/* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP	0x02000000	/* mprotect flag: extend change to end of growsdown vma */

#define MAP_SHARED	0x01		/* Share changes */
#define MAP_PRIVATE	0x02		/* Changes are private */
#define MAP_TYPE	0xf		/* Mask for type of mapping */

#define MADV_REMOVE		9
#define MADV_DONTFORK		10
#define MADV_DOFORK		11
#define MADV_MERGEABLE		12
#define MADV_UNMERGEABLE	13
#define MADV_HUGEPAGE		14
#define MADV_NOHUGEPAGE		15
#define MADV_DONTDUMP		16
#define MADV_DODUMP		17
#define MADV_HWPOISON		100
#define MADV_SOFT_OFFLINE	101

#define MLOCK_ONFAULT	1	/* for mlock2 */

#if defined(__mips__)
#define MAP_FIXED	0x010		/* Interpret addr exactly */
#define MAP_NORESERVE	0x0400		/* don't check for reservations */
#define MAP_ANONYMOUS	0x0800		/* don't use a file */
#define MAP_GROWSDOWN	0x1000		/* stack-like segment */
#define MAP_DENYWRITE	0x2000		/* ETXTBSY */
#define MAP_EXECUTABLE	0x4000		/* mark it as an executable */
#define MAP_LOCKED	0x8000		/* pages are locked */
#define MAP_POPULATE	0x10000
#define MAP_NONBLOCK	0x20000
#define MAP_STACK	0x40000
#define MAP_HUGETLB	0x80000
#define MS_ASYNC	0x0001		/* sync memory asynchronously */
#define MS_INVALIDATE	0x0002		/* invalidate mappings & caches */
#define MS_SYNC		0x0004		/* synchronous memory sync */
#define MCL_CURRENT	1		/* lock all current mappings */
#define MCL_FUTURE	2		/* lock all future mappings */
#define MCL_ONFAULT	4		/* lock all pages that are faulted in */
#define MADV_NORMAL	0x0		/* default page-in behavior */
#define MADV_RANDOM	0x1		/* page-in minimum required */
#define MADV_SEQUENTIAL	0x2		/* read-ahead aggressively */
#define MADV_WILLNEED	0x3		/* pre-fault pages */
#define MADV_DONTNEED	0x4		/* discard these pages */
#elif defined(__alpha__)
#define MAP_FIXED	0x100		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x10		/* don't use a file */
#define MAP_GROWSDOWN	0x1000		/* stack-like segment */
#define MAP_DENYWRITE	0x2000		/* ETXTBSY */
#define MAP_EXECUTABLE	0x4000		/* mark it as an executable */
#define MAP_LOCKED	0x8000		/* lock the mapping */
#define MAP_NORESERVE	0x10000		/* don't check for reservations */
#define MAP_POPULATE	0x20000
#define MAP_NONBLOCK	0x40000
#define MAP_STACK	0x80000
#define MAP_HUGETLB	0x100000
#define MS_ASYNC	1		/* sync memory asynchronously */
#define MS_SYNC		2		/* synchronous memory sync */
#define MS_INVALIDATE	4		/* invalidate the caches */
#define MCL_CURRENT	 8192		/* lock all currently mapped pages */
#define MCL_FUTURE	16384		/* lock all additions to address space */
#define MCL_ONFAULT	32768		/* lock all pages that are faulted in */
#define MADV_NORMAL	0		/* no further special treatment */
#define MADV_RANDOM	1		/* expect random page references */
#define MADV_SEQUENTIAL	2		/* expect sequential page references */
#define MADV_WILLNEED	3		/* will need these pages */
#define MADV_SPACEAVAIL	5		/* ensure resources are available */
#define MADV_DONTNEED	6		/* dont need these pages */

#elif defined(__i386__) || defined(__s390__) || defined(__x86_64__) || defined(__arm__)
#define MAP_FIXED	0x10		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20		/* don't use a file */
#define MAP_GROWSDOWN	0x0100		/* stack-like segment */
#define MAP_DENYWRITE	0x0800		/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000		/* mark it as an executable */
#define MAP_LOCKED	0x2000		/* pages are locked */
#define MAP_NORESERVE	0x4000		/* don't check for reservations */
#define MAP_POPULATE	0x8000
#define MAP_NONBLOCK	0x10000
#define MAP_STACK	0x20000
#define MAP_HUGETLB	0x40000
#define MS_ASYNC	1		/* sync memory asynchronously */
#define MS_INVALIDATE	2		/* invalidate the caches */
#define MS_SYNC		4		/* synchronous memory sync */
#define MCL_CURRENT	1		/* lock all current mappings */
#define MCL_FUTURE	2		/* lock all future mappings */
#define MCL_ONFAULT	4		/* lock all pages that are faulted in */
#define MADV_NORMAL	0x0		/* default page-in behavior */
#define MADV_RANDOM	0x1		/* page-in minimum required */
#define MADV_SEQUENTIAL	0x2		/* read-ahead aggressively */
#define MADV_WILLNEED	0x3		/* pre-fault pages */
#define MADV_DONTNEED	0x4		/* discard these pages */

#elif defined(__sparc__) || defined (__powerpc__) || defined (__powerpc64__)
#define MAP_FIXED	0x10		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20		/* don't use a file */
#define MAP_RENAME	MAP_ANONYMOUS	/* In SunOS terminology */
#define MAP_NORESERVE	0x40		/* don't reserve swap pages */
#define MAP_INHERIT	0x80		/* SunOS doesn't do this, but... */
#define MAP_LOCKED	0x100		/* lock the mapping */
#define _MAP_NEW	0x80000000	/* Binary compatibility is fun... */
#define MAP_GROWSDOWN	0x0100		/* stack-like segment */
#define MAP_DENYWRITE	0x0800		/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000		/* mark it as an executable */
#define MAP_POPULATE	0x8000
#define MAP_NONBLOCK	0x10000
#define MAP_STACK	0x20000
#define MAP_HUGETLB	0x40000
#define MS_ASYNC	1		/* sync memory asynchronously */
#define MS_INVALIDATE	2		/* invalidate the caches */
#define MS_SYNC		4		/* synchronous memory sync */
#define MCL_CURRENT	0x2000		/* lock all currently mapped pages */
#define MCL_FUTURE	0x4000		/* lock all additions to address space */
#define MCL_ONFAULT	0x8000		/* lock all pages that are fauled in */
#define MADV_NORMAL	0x0		/* default page-in behavior */
#define MADV_RANDOM	0x1		/* page-in minimum required */
#define MADV_SEQUENTIAL	0x2		/* read-ahead aggressively */
#define MADV_WILLNEED	0x3		/* pre-fault pages */
#define MADV_DONTNEED	0x4		/* discard these pages */
#define MADV_FREE	0x5		/* (Solaris) contents can be freed */

#elif defined(__aarch64__)
#define MAP_FIXED	0x10		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20		/* don't use a file */
#define MAP_GROWSDOWN	0x00100		/* Stack-like segment.  */
#define MAP_DENYWRITE	0x00800		/* ETXTBSY */
#define MAP_EXECUTABLE	0x01000		/* Mark it as an executable.  */
#define MAP_LOCKED	0x02000		/* Lock the mapping.  */
#define MAP_NORESERVE	0x04000		/* Don't check for reservations.  */
#define MAP_POPULATE	0x08000		/* Populate (prefault) pagetables.  */
#define MAP_NONBLOCK	0x10000		/* Do not block on IO.  */
#define MAP_STACK	0x20000		/* Allocation is for a stack.  */
#define MAP_HUGETLB	0x40000		/* Create huge page mapping.  */
#define MS_ASYNC	1		/* sync memory asynchronously */
#define MS_INVALIDATE	2		/* invalidate the caches */
#define MS_SYNC		4		/* synchronous memory sync */
#define MCL_CURRENT	1		/* lock all currently mapped pages */
#define MCL_FUTURE	2		/* lock all additions to address space */
#define MCL_ONFAULT	4		/* lock all pages that are faulted in */
#define MADV_NORMAL	 0	/* No further special treatment.  */
#define MADV_RANDOM	 1	/* Expect random page references.  */
#define MADV_SEQUENTIAL	 2	/* Expect sequential page references.  */
#define MADV_WILLNEED	 3	/* Will need these pages.  */
#define MADV_DONTNEED	 4	/* Don't need these pages.  */
#define MADV_REMOVE	 9	/* Remove these pages and resources.  */
#define MADV_DONTFORK	 10	/* Do not inherit across fork.  */
#define MADV_DOFORK	 11	/* Do inherit across fork.  */
#define MADV_MERGEABLE	 12	/* KSM may merge identical pages.  */
#define MADV_UNMERGEABLE 13	/* KSM may not merge identical pages.  */
#define MADV_HUGEPAGE	 14	/* Worth backing with hugepages.  */
#define MADV_NOHUGEPAGE	 15	/* Not worth backing with hugepages.  */
#define MADV_DONTDUMP	 16	/* Explicity exclude from the core dump,
				   overrides the coredump filter bits.  */
#define MADV_DODUMP	 17	/* Clear the MADV_DONTDUMP flag.  */
#define MADV_HWPOISON	 100	/* Poison a page for testing.  */

#elif defined(__hppa__)
#undef MAP_TYPE
#define MAP_TYPE	0x03	/* Mask for type of mapping */
#define MAP_FIXED	0x04	/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x10	/* don't use a file */

#define MAP_DENYWRITE	0x0800	/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000	/* mark it as an executable */
#define MAP_LOCKED	0x2000	/* pages are locked */
#define MAP_NORESERVE	0x4000	/* don't check for reservations */
#define MAP_GROWSDOWN	0x8000	/* stack-like segment */
#define MAP_POPULATE	0x10000
#define MAP_NONBLOCK	0x20000
#define MAP_STACK	0x40000
#define MAP_HUGETLB	0x80000

#define MS_SYNC 	1	/* synchronous memory sync */
#define MS_ASYNC	2	/* sync memory asynchronously */
#define MS_INVALIDATE	4	/* invalidate the caches */

#define MCL_CURRENT	1	/* lock all current mappings */
#define MCL_FUTURE	2
#define MCL_ONFAULT	4		/* lock all pages that are faulted in */

#define MADV_NORMAL	0	/* no further special treatment */
#define MADV_RANDOM	1	/* expect random page references */
#define MADV_SEQUENTIAL 2	/* expect sequential page references */
#define MADV_WILLNEED	3	/* will need these pages */
#define MADV_DONTNEED	4	/* don't need these pages */
#define MADV_SPACEAVAIL 5	/* insure that resources are reserved */
#define MADV_VPS_PURGE	6	/* Purge pages from VM page cache */
#define MADV_VPS_INHERIT 7	/* Inherit parents page size */
#define MADV_4K_PAGES	12	/* Use 4K pages	 */
#define MADV_16K_PAGES	14	/* Use 16K pages */
#define MADV_64K_PAGES	16	/* Use 64K pages */
#define MADV_256K_PAGES 18	/* Use 256K pages */
#define MADV_1M_PAGES	20	/* Use 1 Megabyte pages */
#define MADV_4M_PAGES	22	/* Use 4 Megabyte pages */
#define MADV_16M_PAGES	24	/* Use 16 Megabyte pages */
#define MADV_64M_PAGES	26	/* Use 64 Megabyte pages */

#undef MADV_MERGEABLE
#undef MADV_UNMERGEABLE
#undef MADV_HUGEPAGE
#undef MADV_NOHUGEPAGE
#undef MADV_DONTDUMP
#undef MADV_DODUMP

#define MADV_MERGEABLE 65
#define MADV_UNMERGEABLE 66
#define MADV_HUGEPAGE 67
#define MADV_NOHUGEPAGE 68
#define MADV_DONTDUMP 69
#define MADV_DODUMP 70

#elif defined(__ia64__)

#define MAP_FIXED	0x10	/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20	/* don't use a file */

#define MAP_GROWSDOWN	0x0100	/* stack-like segment */
#define MAP_GROWSUP	0x0200	/* register stack-like segment */
#define MAP_DENYWRITE	0x0800	/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000	/* mark it as an executable */
#define MAP_LOCKED	0x2000	/* pages are locked */
#define MAP_NORESERVE	0x4000	/* don't check for reservations */
#define MAP_POPULATE	0x8000
#define MAP_NONBLOCK	0x10000
#define MAP_STACK	0x20000
#define MAP_HUGETLB	0x40000

#define MS_ASYNC	1	/* sync memory asynchronously */
#define MS_INVALIDATE	2	/* invalidate the caches */
#define MS_SYNC 	4	/* synchronous memory sync */

#define MADV_NORMAL     0x0	/* default page-in behavior */
#define MADV_RANDOM     0x1	/* page-in minimum required */
#define MADV_SEQUENTIAL 0x2	/* read-ahead aggressively */
#define MADV_WILLNEED   0x3	/* pre-fault pages */
#define MADV_DONTNEED   0x4	/* discard these pages */
#endif

/* compatibility flags */
#define MAP_ANON	MAP_ANONYMOUS
#define MAP_FILE	0

#define MAP_FAILED      ((void *) -1)

__attribute__((__warn_unused_result__))
extern void *mmap (void *__addr, size_t __len, int __prot,
                   int __flags, int __fd, off_t __offset);

extern int munmap (void *__addr, size_t __len) __THROW;
extern int mprotect (void *__addr, size_t __len, int __prot) __THROW;
extern int msync (void *__addr, size_t __len, int __flags) __THROW;

__attribute__((__warn_unused_result__))
extern void *mremap (void *__addr, size_t __old_len, size_t __new_len,
		     unsigned long __may_move) __THROW;
extern int mincore (void *__start, size_t __len, unsigned char *__vec);

__attribute__((__warn_unused_result__))
extern void *mmap64 (void *__addr, size_t __len, int __prot,
		     int __flags, int __fd, off64_t __offset) __THROW;

#ifndef __NO_STAT64
#if defined _FILE_OFFSET_BITS && _FILE_OFFSET_BITS == 64
#define mmap(a,b,c,d,e,f) mmap64(a,b,c,d,e,f)
#endif
#endif

__attribute__((__warn_unused_result__))
int mlockall(int flags) __THROW;

__attribute__((__warn_unused_result__))
int mlock(const void *addr, size_t len) __THROW;
int munlock(const void *addr, size_t len) __THROW;
int munlockall(void) __THROW;

__attribute__((__warn_unused_result__))
int mlock2(const void *addr, size_t len, int flags) __THROW;

int madvise(void *start, size_t length, int advice) __THROW;

#define POSIX_MADV_NORMAL MADV_NORMAL
#define POSIX_MADV_SEQUENTIAL MADV_SEQUENTIAL
#define POSIX_MADV_RANDOM MADV_RANDOM
#define POSIX_MADV_WILLNEED MADV_WILLNEED
#define POSIX_MADV_DONTNEED MADV_DONTNEED

#define posix_madvise(addr,len,advice) madvise(addr,len,advice)

__END_DECLS

#endif
