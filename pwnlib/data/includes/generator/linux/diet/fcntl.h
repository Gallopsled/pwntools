#ifndef _FCNTL_H
#define _FCNTL_H

#include <sys/cdefs.h>

#include <endian.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

__BEGIN_DECLS

#define F_LINUX_SPECIFIC_BASE	1024

#if defined(__i386__) || defined(__s390__) || defined(__x86_64__) || defined(__ia64__)

/* open/fcntl - O_SYNC is only implemented on blocks devices and on files
   located on an ext2 file system */
#define O_ACCMODE	   0003
#define O_RDONLY	     00
#define O_WRONLY	     01
#define O_RDWR		     02
#define O_CREAT		   0100	/* not fcntl */
#define O_EXCL		   0200	/* not fcntl */
#define O_NOCTTY	   0400	/* not fcntl */
#define O_TRUNC		  01000	/* not fcntl */
#define O_APPEND	  02000
#define O_NONBLOCK	  04000
#define O_NDELAY	O_NONBLOCK
#define O_SYNC		 010000
#define FASYNC		 020000	/* fcntl, for BSD compatibility */
#define O_DIRECT	 040000	/* direct disk access hint - currently ignored */
#define O_LARGEFILE	0100000
#define O_DIRECTORY	0200000	/* must be a directory */
#define O_NOFOLLOW	0400000 /* don't follow links */
#define O_NOATIME	01000000

#define F_DUPFD		0	/* dup */
#define F_GETFD		1	/* get close_on_exec */
#define F_SETFD		2	/* set/clear close_on_exec */
#define F_GETFL		3	/* get file->f_flags */
#define F_SETFL		4	/* set file->f_flags */
#define F_GETLK		5
#define F_SETLK		6
#define F_SETLKW	7
#define F_SETOWN	8	/*  for sockets. */
#define F_GETOWN	9	/*  for sockets. */
#define F_SETSIG	10	/*  for sockets. */
#define F_GETSIG	11	/*  for sockets. */

#define F_GETLK64	12	/*  using 'struct flock64' */
#define F_SETLK64	13
#define F_SETLKW64	14

#define FD_CLOEXEC	1	/* actually anything with low bit set goes */

/* for posix fcntl() and lockf() */
#define F_RDLCK		0
#define F_WRLCK		1
#define F_UNLCK		2

/* for old implementation of bsd flock () */
#define F_EXLCK		4	/* or 3 */
#define F_SHLCK		8	/* or 4 */

/* for leases */
#define F_INPROGRESS	16

/* operations for bsd flock(), also used by the kernel implementation */
#define LOCK_SH		1	/* shared lock */
#define LOCK_EX		2	/* exclusive lock */
#define LOCK_NB		4	/* or'd with one of the above to prevent
				   blocking */
#define LOCK_UN		8	/* remove lock */

#define LOCK_MAND	32	/* This is a mandatory flock */
#define LOCK_READ	64	/* ... Which allows concurrent read operations */
#define LOCK_WRITE	128	/* ... Which allows concurrent write operations */
#define LOCK_RW		192	/* ... Which allows concurrent read & write ops */

struct flock {
  int16_t l_type;
  int16_t l_whence;
  off_t l_start;
  off_t l_len;
  pid_t l_pid;
};

struct flock64 {
  int16_t l_type;
  int16_t l_whence;
  loff_t l_start;
  loff_t l_len;
  pid_t  l_pid;
};

#elif defined(__alpha__)

/* open/fcntl - O_SYNC is only implemented on blocks devices and on files
   located on an ext2 file system */
#define O_ACCMODE	  0003
#define O_RDONLY	    00
#define O_WRONLY	    01
#define O_RDWR		    02
#define O_CREAT		 01000	/* not fcntl */
#define O_TRUNC		 02000	/* not fcntl */
#define O_EXCL		 04000	/* not fcntl */
#define O_NOCTTY	010000	/* not fcntl */

#define O_NONBLOCK	 00004
#define O_APPEND	 00010
#define O_NDELAY	O_NONBLOCK
#define O_SYNC		040000
#define FASYNC		020000	/* fcntl, for BSD compatibility */
#define O_DIRECTORY	0100000	/* must be a directory */
#define O_NOFOLLOW	0200000 /* don't follow links */
#define O_LARGEFILE	0400000 /* will be set by the kernel on every open */
#define O_DIRECT	02000000	/* direct disk access - should check with OSF/1 */
#define O_NOATIME	04000000

#define F_DUPFD		0	/* dup */
#define F_GETFD		1	/* get close_on_exec */
#define F_SETFD		2	/* set/clear close_on_exec */
#define F_GETFL		3	/* get file->f_flags */
#define F_SETFL		4       /* set file->f_flags */
#define F_GETLK		7
#define F_SETLK		8
#define F_SETLKW	9

#define F_SETOWN	5	/*  for sockets. */
#define F_GETOWN	6	/*  for sockets. */
#define F_SETSIG	10	/*  for sockets. */
#define F_GETSIG	11	/*  for sockets. */

/* for F_[GET|SET]FL */
#define FD_CLOEXEC	1	/* actually anything with low bit set goes */

/* for posix fcntl() and lockf() */
#define F_RDLCK		1
#define F_WRLCK		2
#define F_UNLCK		8

/* for old implementation of bsd flock () */
#define F_EXLCK		16	/* or 3 */
#define F_SHLCK		32	/* or 4 */

#define F_INPROGRESS	64

/* operations for bsd flock(), also used by the kernel implementation */
#define LOCK_SH		1	/* shared lock */
#define LOCK_EX		2	/* exclusive lock */
#define LOCK_NB		4	/* or'd with one of the above to prevent
				   blocking */
#define LOCK_UN		8	/* remove lock */
#define LOCK_MAND      32      /* This is a mandatory flock */
#define LOCK_READ      64      /* ... Which allows concurrent read operations */
#define LOCK_WRITE     128     /* ... Which allows concurrent write operations */
#define LOCK_RW        192     /* ... Which allows concurrent read & write ops */

struct flock {
  int16_t l_type;
  int16_t l_whence;
  off_t l_start;
  off_t l_len;
  pid_t l_pid;
};

#elif defined(__mips__)

/* open/fcntl - O_SYNC is only implemented on blocks devices and on files
   located on an ext2 file system */
#define O_ACCMODE	0x0003
#define O_RDONLY	0x0000
#define O_WRONLY	0x0001
#define O_RDWR		0x0002
#define O_APPEND	0x0008
#define O_SYNC		0x0010
#define O_NONBLOCK	0x0080
#define O_CREAT         0x0100	/* not fcntl */
#define O_TRUNC		0x0200	/* not fcntl */
#define O_EXCL		0x0400	/* not fcntl */
#define O_NOCTTY	0x0800	/* not fcntl */
#define FASYNC		0x1000	/* fcntl, for BSD compatibility */
#define O_LARGEFILE	0x2000	/* allow large file opens - currently ignored */
#define O_DIRECT	0x8000	/* direct disk access hint - currently ignored */
#define O_DIRECTORY	0x10000	/* must be a directory */
#define O_NOFOLLOW	0x20000	/* don't follow links */
#define O_NOATIME	0x40000

#define O_NDELAY	O_NONBLOCK

#define F_DUPFD		0	/* dup */
#define F_GETFD		1	/* get close_on_exec */
#define F_SETFD		2	/* set/clear close_on_exec */
#define F_GETFL		3	/* get file->f_flags */
#define F_SETFL		4	/* set file->f_flags */
#define F_GETLK		14
#define F_SETLK		6
#define F_SETLKW	7

#define F_SETOWN	24	/*  for sockets. */
#define F_GETOWN	23	/*  for sockets. */
#define F_SETSIG	10	/*  for sockets. */
#define F_GETSIG	11	/*  for sockets. */

#ifndef __mips64__
#define F_GETLK64	33	/*  using 'struct flock64' */
#define F_SETLK64	34
#define F_SETLKW64	35
#endif

/* for F_[GET|SET]FL */
#define FD_CLOEXEC	1	/* actually anything with low bit set goes */

/* for posix fcntl() and lockf() */
#define F_RDLCK		0
#define F_WRLCK		1
#define F_UNLCK		2

/* for old implementation of bsd flock () */
#define F_EXLCK		4	/* or 3 */
#define F_SHLCK		8	/* or 4 */

/* for leases */
#define F_INPROGRESS	16

/* operations for bsd flock(), also used by the kernel implementation */
#define LOCK_SH		1	/* shared lock */
#define LOCK_EX		2	/* exclusive lock */
#define LOCK_NB		4	/* or'd with one of the above to prevent		XXXXXXXXXXXXXXXXXX
				   blocking */
#define LOCK_UN		8	/* remove lock */

#define LOCK_MAND	32	/* This is a mandatory flock */
#define LOCK_READ	64	/* ... Which allows concurrent read operations */
#define LOCK_WRITE	128	/* ... Which allows concurrent write operations */
#define LOCK_RW		192	/* ... Which allows concurrent read & write ops */

#ifndef __mips64__
struct flock {
  int16_t l_type;
  int16_t l_whence;
  off_t l_start;
  off_t l_len;
  long  l_sysid;			/* XXXXXXXXXXXXXXXXXXXXXXXXX */
  pid_t l_pid;
  long  pad[4];			/* ZZZZZZZZZZZZZZZZZZZZZZZZZZ */
};
struct flock64 {
  int16_t l_type;
  int16_t l_whence;
  loff_t l_start;
  loff_t l_len;
  pid_t l_pid;
};
#else
struct flock {
  int16_t l_type;
  int16_t l_whence;
  off_t l_start;
  off_t l_len;
  pid_t l_pid;
};
#define flock64 flock
#endif

#elif defined(__sparc__)

/* open/fcntl - O_SYNC is only implemented on blocks devices and on files
   located on an ext2 file system */
#define O_RDONLY	0x0000
#define O_WRONLY	0x0001
#define O_RDWR		0x0002
#define O_ACCMODE	0x0003
#define O_APPEND	0x0008
#define FASYNC		0x0040	/* fcntl, for BSD compatibility */
#define O_CREAT		0x0200	/* not fcntl */
#define O_TRUNC		0x0400	/* not fcntl */
#define O_EXCL		0x0800	/* not fcntl */
#define O_SYNC		0x2000
#define O_NONBLOCK	0x4000
#define O_NDELAY	(0x0004 | O_NONBLOCK)
#define O_NOCTTY	0x8000	/* not fcntl */
#define O_DIRECTORY	0x10000	/* must be a directory */
#define O_NOFOLLOW	0x20000	/* don't follow links */
#define O_LARGEFILE	0x40000
#define O_DIRECT        0x100000 /* direct disk access hint */
#define O_NOATIME	0x200000

#define F_DUPFD		0	/* dup */
#define F_GETFD		1	/* get close_on_exec */
#define F_SETFD		2	/* set/clear close_on_exec */
#define F_GETFL		3	/* get file->f_flags */
#define F_SETFL		4	/* set file->f_flags */
#define F_GETOWN	5	/*  for sockets. */
#define F_SETOWN	6	/*  for sockets. */
#define F_GETLK		7
#define F_SETLK		8
#define F_SETLKW	9
#define F_SETSIG	10	/*  for sockets. */
#define F_GETSIG	11	/*  for sockets. */

#define F_GETLK64	12	/*  using 'struct flock64' */
#define F_SETLK64	13
#define F_SETLKW64	14

/* for F_[GET|SET]FL */
#define FD_CLOEXEC	1	/* actually anything with low bit set goes */

/* for posix fcntl() and lockf() */
#define F_RDLCK		1
#define F_WRLCK		2
#define F_UNLCK		3

/* for old implementation of bsd flock () */
#define F_EXLCK		4	/* or 3 */
#define F_SHLCK		8	/* or 4 */

/* for leases */
#define F_INPROGRESS	16

/* operations for bsd flock(), also used by the kernel implementation */
#define LOCK_SH		1	/* shared lock */
#define LOCK_EX		2	/* exclusive lock */
#define LOCK_NB		4	/* or'd with one of the above to prevent
				   blocking */
#define LOCK_UN		8	/* remove lock */

#define LOCK_MAND	32	/* This is a mandatory flock */
#define LOCK_READ	64	/* ... Which allows concurrent read operations */
#define LOCK_WRITE	128	/* ... Which allows concurrent write operations */
#define LOCK_RW		192	/* ... Which allows concurrent read & write ops */

struct flock {
  int16_t l_type;
  int16_t l_whence;
  off_t l_start;
  off_t l_len;
  pid_t l_pid;
  int16_t __unused;
};

#ifdef __arch64__
#define flock64 flock
#else
struct flock64 {
  int16_t l_type;
  int16_t l_whence;
  loff_t l_start;
  loff_t l_len;
  pid_t l_pid;
  int16_t __unused;
};
#endif

#elif defined(__powerpc__) || defined(__powerpc64__)

/* open/fcntl - O_SYNC is only implemented on blocks devices and on files
   located on an ext2 file system */
#define O_ACCMODE	   0003
#define O_RDONLY	     00
#define O_WRONLY	     01
#define O_RDWR		     02
#define O_CREAT		   0100	/* not fcntl */
#define O_EXCL		   0200	/* not fcntl */
#define O_NOCTTY	   0400	/* not fcntl */
#define O_TRUNC		  01000	/* not fcntl */
#define O_APPEND	  02000
#define O_NONBLOCK	  04000
#define O_NDELAY	O_NONBLOCK
#define O_SYNC		 010000
#define FASYNC		 020000	/* fcntl, for BSD compatibility */
#define O_DIRECTORY      040000	/* must be a directory */
#define O_NOFOLLOW      0100000	/* don't follow links */
#define O_LARGEFILE     0200000
#define O_DIRECT	0400000	/* direct disk access hint - currently ignored */
#define O_NOATIME	01000000

#define F_DUPFD		0	/* dup */
#define F_GETFD		1	/* get close_on_exec */
#define F_SETFD		2	/* set/clear close_on_exec */
#define F_GETFL		3	/* get file->f_flags */
#define F_SETFL		4	/* set file->f_flags */
#define F_GETLK		5
#define F_SETLK		6
#define F_SETLKW	7

#define F_SETOWN	8	/*  for sockets. */
#define F_GETOWN	9	/*  for sockets. */
#define F_SETSIG	10	/*  for sockets. */
#define F_GETSIG	11	/*  for sockets. */

#define F_GETLK64	12	/*  using 'struct flock64' */
#define F_SETLK64	13
#define F_SETLKW64	14

/* for F_[GET|SET]FL */
#define FD_CLOEXEC	1	/* actually anything with low bit set goes */

/* for posix fcntl() and lockf() */
#define F_RDLCK		0
#define F_WRLCK		1
#define F_UNLCK		2

/* for old implementation of bsd flock () */
#define F_EXLCK		4	/* or 3 */
#define F_SHLCK		8	/* or 4 */

/* for leases */
#define F_INPROGRESS	16

/* operations for bsd flock(), also used by the kernel implementation */
#define LOCK_SH		1	/* shared lock */
#define LOCK_EX		2	/* exclusive lock */
#define LOCK_NB		4	/* or'd with one of the above to prevent
				   blocking */
#define LOCK_UN		8	/* remove lock */

#define LOCK_MAND	32	/* This is a mandatory flock */
#define LOCK_READ	64	/* ... Which allows concurrent read operations */
#define LOCK_WRITE	128	/* ... Which allows concurrent write operations */
#define LOCK_RW		192	/* ... Which allows concurrent read & write ops */

struct flock {
  int16_t l_type;
  int16_t l_whence;
  off_t l_start;
  off_t l_len;
  pid_t l_pid;
};

struct flock64 {
  int16_t l_type;
  int16_t l_whence;
  loff_t l_start;
  loff_t l_len;
  pid_t  l_pid;
};

#elif defined (__arm__)

/* open/fcntl - O_SYNC is only implemented on blocks devices and on files
   located on an ext2 file system */
#define O_ACCMODE	   0003
#define O_RDONLY	     00
#define O_WRONLY	     01
#define O_RDWR		     02
#define O_CREAT		   0100	/* not fcntl */
#define O_EXCL		   0200	/* not fcntl */
#define O_NOCTTY	   0400	/* not fcntl */
#define O_TRUNC		  01000	/* not fcntl */
#define O_APPEND	  02000
#define O_NONBLOCK	  04000
#define O_NDELAY	O_NONBLOCK
#define O_SYNC		 010000
#define FASYNC		 020000	/* fcntl, for BSD compatibility */
#define O_DIRECTORY	 040000	/* must be a directory */
#define O_NOFOLLOW	0100000	/* don't follow links */
#define O_DIRECT	0200000	/* direct disk access hint - currently ignored */
#define O_LARGEFILE	0400000
#define O_NOATIME	01000000

#define F_DUPFD		0	/* dup */
#define F_GETFD		1	/* get close_on_exec */
#define F_SETFD		2	/* set/clear close_on_exec */
#define F_GETFL		3	/* get file->f_flags */
#define F_SETFL		4	/* set file->f_flags */
#define F_GETLK		5
#define F_SETLK		6
#define F_SETLKW	7

#define F_SETOWN	8	/*  for sockets. */
#define F_GETOWN	9	/*  for sockets. */
#define F_SETSIG	10	/*  for sockets. */
#define F_GETSIG	11	/*  for sockets. */

#define F_GETLK64	12	/*  using 'struct flock64' */
#define F_SETLK64	13
#define F_SETLKW64	14

/* for F_[GET|SET]FL */
#define FD_CLOEXEC	1	/* actually anything with low bit set goes */

/* for posix fcntl() and lockf() */
#define F_RDLCK		0
#define F_WRLCK		1
#define F_UNLCK		2

/* for old implementation of bsd flock () */
#define F_EXLCK		4	/* or 3 */
#define F_SHLCK		8	/* or 4 */

/* for leases */
#define F_INPROGRESS	16

/* operations for bsd flock(), also used by the kernel implementation */
#define LOCK_SH		1	/* shared lock */
#define LOCK_EX		2	/* exclusive lock */
#define LOCK_NB		4	/* or'd with one of the above to prevent
				   blocking */
#define LOCK_UN		8	/* remove lock */

#define LOCK_MAND	32	/* This is a mandatory flock */
#define LOCK_READ	64	/* ... Which allows concurrent read operations */
#define LOCK_WRITE	128	/* ... Which allows concurrent write operations */
#define LOCK_RW		192	/* ... Which allows concurrent read & write ops */

struct flock {
  int16_t l_type;
  int16_t l_whence;
  off_t l_start;
  off_t l_len;
  pid_t l_pid;
};

struct flock64 {
  int16_t l_type;
  int16_t l_whence;
  loff_t l_start;
  loff_t l_len;
  pid_t  l_pid;
};

#elif defined(__hppa__)

/* Copied from bits/fcntl.h */

#define O_RDONLY    00000000
#define O_WRONLY    00000001
#define O_RDWR      00000002
#define O_ACCMODE   00000003
#define O_APPEND    00000010
#define O_BLKSEEK   00000100 /* HPUX only */
#define O_CREAT     00000400 /* not fcntl */
#define O_TRUNC     00001000 /* not fcntl */
#define O_EXCL      00002000 /* not fcntl */
#define O_LARGEFILE 00004000
#define O_ASYNC     00020000
#define O_SYNC      00100000
#define O_NONBLOCK  00200004 /* HPUX has separate NDELAY & NONBLOCK */
#define O_NDELAY    O_NONBLOCK
#define O_NOCTTY    00400000 /* not fcntl */
#define O_DSYNC     01000000 /* HPUX only */
#define O_RSYNC     02000000 /* HPUX only */
#define O_NOATIME   04000000
#define O_DIRECTORY  00010000

#define O_DIRECT    00040000 /* direct disk access hint - currently ignored */
#define O_NOFOLLOW  00000200 /* don't follow links */
#define O_INVISIBLE 04000000 /* invisible I/O, for DMAPI/XDSM */

#define F_DUPFD     0   /* Duplicate file descriptor.  */
#define F_GETFD     1   /* Get file descriptor flags.  */
#define F_SETFD     2   /* Set file descriptor flags.  */
#define F_GETFL     3   /* Get file status flags.  */
#define F_SETFL     4   /* Set file status flags.  */
#define F_GETLK     5   /* Get record locking info.  */
#define F_SETLK     6   /* Set record locking info (non-blocking).  */
#define F_SETLKW    7   /* Set record locking info (blocking).  */

#define F_GETLK64   8   /* Get record locking info.  */
#define F_SETLK64   9   /* Set record locking info (non-blocking).  */
#define F_SETLKW64  10  /* Set record locking info (blocking).  */

#define F_GETOWN    11 /*  for sockets. */
#define F_SETOWN    12 /*  for sockets. */
#define F_SETSIG    13 /*  for sockets. */
#define F_GETSIG    14 /*  for sockets. */

#define FD_CLOEXEC  1   /* actually anything with low bit set goes */

#define F_RDLCK     1   /* Read lock.  */
#define F_WRLCK     2   /* Write lock.  */
#define F_UNLCK     3   /* Remove lock.  */

#define F_EXLCK     4   /* or 3 */
#define F_SHLCK     8   /* or 4 */

/* for leases */
#define F_INPROGRESS   16

/* operations for bsd flock(), also used by the kernel implementation */
#define LOCK_SH                1       /* shared lock */
#define LOCK_EX                2       /* exclusive lock */
#define LOCK_NB                4       /* or'd with one of the above to prevent blocking */
#define LOCK_UN                8       /* remove lock */

#define LOCK_MAND      32      /* This is a mandatory flock */
#define LOCK_READ      64      /* ... Which allows concurrent read operations */
#define LOCK_WRITE     128     /* ... Which allows concurrent write operations */
#define LOCK_RW                192     /* ... Which allows concurrent read & write ops */


struct flock
{
    int16_t l_type;   /* Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.  */
    int16_t l_whence; /* Where `l_start' is relative to (like `lseek').  */
    off_t l_start;    /* Offset where the lock begins.  */
    off_t l_len;  /* Size of the locked area; zero means until EOF.  */
    pid_t l_pid;  /* Process holding the lock.  */
};

struct flock64
{
    int16_t l_type;   /* Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.  */
    int16_t l_whence; /* Where `l_start' is relative to (like `lseek').  */
    off64_t l_start;  /* Offset where the lock begins.  */
    off64_t l_len;    /* Size of the locked area; zero means until EOF.  */
    pid_t l_pid;  /* Process holding the lock.  */
};

#endif

extern int fcntl (int __fd, int __cmd, ...) __THROW;
#ifndef __NO_STAT64
extern int fcntl64 (int __fd, int __cmd, ...) __THROW;
#if defined _FILE_OFFSET_BITS && _FILE_OFFSET_BITS == 64
#define fcntl fcntl64
#endif
#endif

#if !defined(O_ASYNC) && defined(FASYNC)
#define O_ASYNC FASYNC
#endif

#if defined(_LINUX_SOURCE) || defined(_GNU_SOURCE)
ssize_t readahead(int fd, off64_t *offset, size_t count) __THROW;
#endif

#ifdef _GNU_SOURCE
#define SPLICE_F_MOVE	(0x01)	/* move pages instead of copying */
#define SPLICE_F_NONBLOCK (0x02) /* don't block on the pipe splicing (but */
				 /* we may still block on the fd we splice */
				 /* from/to, of course */
#define SPLICE_F_MORE	(0x04)	/* expect more data */
#define SPLICE_F_GIFT	(0x08)	/* pages passed in are a gift */

long tee(int fd_in, int fd_out, size_t len, unsigned int flags) __THROW;

#include <sys/uio.h>

long vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags) __THROW;
long splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags) __THROW;

int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags) __THROW;

#define FALLOC_FL_KEEP_SIZE 1

int fallocate(int fd, int mode, loff_t offset, loff_t len) __THROW;
#endif

#if defined(_ATFILE_SOURCE) || ((_XOPEN_SOURCE + 0) >= 700) || ((_POSIX_C_SOURCE + 0) >= 200809L)
#define AT_FDCWD		-100    /* Special value used to indicate openat should use the current working directory. */
#define AT_SYMLINK_NOFOLLOW	0x100   /* Do not follow symbolic links.  */
#define AT_REMOVEDIR		0x200   /* Remove directory instead of unlinking file.  */
#define AT_SYMLINK_FOLLOW	0x400   /* Follow symbolic links.  */

int openat(int dirfd, const char *pathname, int flags, ...) __THROW;
int futimesat(int dirfd, const char *pathname, const struct timeval times[2]) __THROW;
int unlinkat(int dirfd, const char *pathname, int flags) __THROW;
#endif

#if defined(_XOPEN_SOURCE) && (_XOPEN_SOURCE - 0) >= 600
#include "linux/fadvise.h"
int posix_fallocate(int fd, off64_t offset, off64_t len) __THROW;
int posix_fadvise(int fd, off64_t offset, off64_t len, int advice) __THROW;
#endif

__END_DECLS

#endif
