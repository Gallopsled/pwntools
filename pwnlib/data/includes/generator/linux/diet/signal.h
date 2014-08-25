#ifndef _SIGNAL_H
#define _SIGNAL_H

#include <sys/cdefs.h>

__BEGIN_DECLS

#define __WANT_POSIX1B_SIGNALS__

#include <sys/types.h>
#include <endian.h>

#define NSIG		32

#ifdef __mips__
#define _NSIG		128
#else
#define _NSIG		64
#endif

#define SIGHUP		 1
#define SIGINT		 2
#define SIGQUIT		 3
#define SIGILL		 4
#define SIGTRAP		 5
#define SIGABRT		 6
#define SIGIOT		 6
#define SIGFPE		 8
#define SIGKILL		 9
#define SIGSEGV		11
#define SIGPIPE		13
#define SIGALRM		14
#define SIGTERM		15
#define SIGUNUSED	31
#if defined(__i386__) || defined(__x86_64__) || defined(__powerpc__) || defined(__arm__) \
	|| defined(__s390__) || defined(__ia64__) || defined(__powerpc64__)
#define SIGBUS		 7
#define SIGUSR1		10
#define SIGUSR2		12
#define SIGSTKFLT	16
#define SIGCHLD		17
#define SIGCONT		18
#define SIGSTOP		19
#define SIGTSTP		20
#define SIGTTIN		21
#define SIGTTOU		22
#define SIGURG		23
#define SIGXCPU		24
#define SIGXFSZ		25
#define SIGVTALRM	26
#define SIGPROF		27
#define SIGWINCH	28
#define SIGIO		29
#define SIGPWR		30
#define SIGSYS		31
#elif defined(__alpha__) || defined(__sparc__)
#define SIGEMT		 7
#define SIGBUS		10
#define SIGSYS		12
#define SIGURG		16
#define SIGSTOP		17
#define SIGTSTP		18
#define SIGCONT		19
#define SIGCHLD		20
#define SIGTTIN		21
#define SIGTTOU		22
#define SIGIO		23
#define SIGXCPU		24
#define SIGXFSZ		25
#define SIGVTALRM	26
#define SIGPROF		27
#define SIGWINCH	28
#define SIGPWR		29
#define SIGUSR1		30
#define SIGUSR2		31
#if defined(__alpha__)
#define SIGINFO		SIGPWR
#endif
#elif defined(__mips__)
#define SIGEMT		 7
#define SIGBUS		10
#define SIGSYS		12
#define SIGUSR1		16
#define SIGUSR2		17
#define SIGCHLD		18
#define SIGPWR		19
#define SIGWINCH	20
#define SIGURG		21
#define SIGIO		22
#define SIGSTOP		23
#define SIGTSTP		24
#define SIGCONT		25
#define SIGTTIN		26
#define SIGTTOU		27
#define SIGVTALRM	28
#define SIGPROF		29
#define SIGXCPU		30
#define SIGXFSZ		31
#elif defined(__hppa__)
#define SIGEMT		 7
#define SIGBUS		10
#define SIGSYS		12
#define SIGUSR1		16
#define SIGUSR2		17
#define SIGCHLD		18
#define SIGPWR		19
#define SIGVTALRM	20
#define SIGPROF		21
#define SIGIO		22
#define SIGWINCH	23
#define SIGSTOP		24
#define SIGTSTP		25
#define SIGCONT		26
#define SIGTTIN		27
#define SIGTTOU		28
#define SIGURG		29
#define SIGLOST		30
#define SIGUNUSED	31
#define SIGRESERVE	SIGUNUSE
#define SIGXCPU		33
#define SIGXFSZ		34
#define SIGSTKFLT	36

#else
#error signal layout not yet known
#endif

#define SIGCLD		SIGCHLD
#define SIGPOLL		SIGIO

/* These should not be considered constants from userland.  */
#ifdef __hppa__
#define SIGRTMIN	37
#else
#define SIGLOST		SIGPWR
#define SIGRTMIN	32
#endif
#define SIGRTMAX	(_NSIG-1)

/* SA_FLAGS values: */
#if defined(__alpha__)
#define SA_ONSTACK	0x00000001
#define SA_RESTART	0x00000002
#define SA_NOCLDSTOP	0x00000004
#define SA_NODEFER	0x00000008
#define SA_RESETHAND	0x00000010
#define SA_NOCLDWAIT	0x00000020 /* not supported yet */
#define SA_SIGINFO	0x00000040
#define SA_INTERRUPT	0x20000000 /* dummy -- ignored */
#elif defined(__hppa__)
#define SA_ONSTACK	0x00000001
#define SA_RESETHAND	0x00000004
#define SA_NOCLDSTOP	0x00000008
#define SA_SIGINFO	0x00000010
#define SA_NODEFER	0x00000020
#define SA_RESTART	0x00000040
#define SA_NOCLDWAIT	0x00000080 /* not supported yet */
#define _SA_SIGGFAULT	0x00000100 /* HPUX */
#define SA_INTERRUPT	0x20000000 /* dummy -- ignored */
#define SA_RESTORER	0x04000000 /* obsolete -- ignored */
#elif defined (__sparc__)
#define SV_SSTACK	1	/* This signal handler should use sig-stack */
#define SV_INTR		2	/* Sig return should not restart system call */
#define SV_RESET	4	/* Set handler to SIG_DFL upon taken signal */
#define SV_IGNCHILD	8	/* Do not send SIGCHLD */

#define SA_NOCLDSTOP	SV_IGNCHILD
#define SA_STACK	SV_SSTACK
#define SA_ONSTACK	SV_SSTACK
#define SA_RESTART	SV_INTR
#define SA_RESETHAND	SV_RESET
#define SA_INTERRUPT	0x10
#define SA_NODEFER	0x20
#define SA_SHIRQ	0x40
#define SA_NOCLDWAIT	0x100	/* not supported yet */
#define SA_SIGINFO	0x200
#else
#if defined (__mips__)
#define SA_NOCLDSTOP	0x00000001
#define SA_SIGINFO	0x00000008
#define SA_NOCLDWAIT	0x00010000 /* Not supported yet */
#else
#define SA_NOCLDSTOP	0x00000001
#define SA_NOCLDWAIT	0x00000002 /* not supported yet */
#define SA_SIGINFO	0x00000004
#endif
#if defined(__arm__)
#define SA_THIRTYTWO	0x02000000
#endif
#define SA_RESTORER	0x04000000
#define SA_ONSTACK	0x08000000
#define SA_RESTART	0x10000000
#define SA_INTERRUPT	0x20000000 /* dummy -- ignored */
#define SA_NODEFER	0x40000000
#define SA_RESETHAND	0x80000000
#endif

/* ugh, historic Linux legacy, for gpm :-( */
#define SA_NOMASK	SA_NODEFER
#define SA_ONESHOT	SA_RESETHAND

/* sigaltstack controls */
#define SS_ONSTACK	1
#define SS_DISABLE	2

#define MINSIGSTKSZ	2048
#define SIGSTKSZ	8192

#if defined(__sparc__)
#define SIG_BLOCK	1
#define SIG_UNBLOCK	2
#define SIG_SETMASK	4
#elif defined(__alpha__) || defined(__mips__)
#define SIG_BLOCK	1
#define SIG_UNBLOCK	2
#define SIG_SETMASK	3
#else
#define SIG_BLOCK	0	/* for blocking signals */
#define SIG_UNBLOCK	1	/* for unblocking signals */
#define SIG_SETMASK	2	/* for setting the signal mask */
#endif

typedef int sig_atomic_t;

typedef void (*sighandler_t)(int);

#ifdef _BSD_SOURCE
typedef sighandler_t sig_t;
#endif

#ifdef _GNU_SOURCE
typedef sighandler_t __sighandler_t;	/* shoot the glibc people! */
#endif

#define SIG_DFL ((sighandler_t)0L)	/* default signal handling */
#define SIG_IGN ((sighandler_t)1L)	/* ignore signal */
#define SIG_ERR ((sighandler_t)-1L)	/* error return from signal */

typedef union sigval {
  int sival_int;
  void *sival_ptr;
} sigval_t;

#define SI_MAX_SIZE	128
#if __WORDSIZE == 64
#define SI_PAD_SIZE	((SI_MAX_SIZE/sizeof(int32_t)) - 4)
#else
#define SI_PAD_SIZE	((SI_MAX_SIZE/sizeof(int32_t)) - 3)
#endif

#ifdef __sparc_v9__
typedef int32_t __band_t;
#else
typedef long __band_t;
#endif

typedef struct siginfo {
  int32_t si_signo;
  int32_t si_errno;
  int32_t si_code;
  union {
    int32_t _pad[SI_PAD_SIZE];
    /* kill() */
    struct {
      pid_t _pid;		/* sender's pid */
      uid_t _uid;		/* sender's uid */
    } _kill;
    /* POSIX.1b timers */
    struct {
      uint32_t _timer1;
      uint32_t _timer2;
    } _timer;
    /* POSIX.1b signals */
    struct {
      pid_t _pid;		/* sender's pid */
      uid_t _uid;		/* sender's uid */
      sigval_t _sigval;
    } _rt;
    /* SIGCHLD */
    struct {
      pid_t _pid;		/* which child */
      uid_t _uid;		/* sender's uid */
      int32_t _status;		/* exit code */
      clock_t _utime;
      clock_t _stime;
    } _sigchld;
    /* SIGILL, SIGFPE, SIGSEGV, SIGBUS */
    struct {
      void *_addr; /* faulting insn/memory ref. */
    } _sigfault;
    /* SIGPOLL */
    struct {
      __band_t _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
      int32_t _fd;
    } _sigpoll;
  } _sifields;
} siginfo_t;

/*
 * How these fields are to be accessed.
 */
#define si_pid		_sifields._kill._pid
#define si_uid		_sifields._kill._uid
#define si_status	_sifields._sigchld._status
#define si_utime	_sifields._sigchld._utime
#define si_stime	_sifields._sigchld._stime
#define si_value	_sifields._rt._sigval
#define si_int		_sifields._rt._sigval.sival_int
#define si_ptr		_sifields._rt._sigval.sival_ptr
#define si_addr		_sifields._sigfault._addr
#define si_band		_sifields._sigpoll._band
#define si_fd		_sifields._sigpoll._fd

/* Values for `si_code'.  Positive values are reserved for kernel-generated
   signals.  */
enum {
  SI_ASYNCNL = -6,		/* Sent by asynch name lookup completion.  */
# define SI_ASYNCNL	SI_ASYNCNL
  SI_SIGIO,			/* Sent by queued SIGIO. */
# define SI_SIGIO	SI_SIGIO
  SI_ASYNCIO,			/* Sent by AIO completion.  */
# define SI_ASYNCIO	SI_ASYNCIO
  SI_MESGQ,			/* Sent by real time mesq state change.  */
# define SI_MESGQ	SI_MESGQ
  SI_TIMER,			/* Sent by timer expiration.  */
# define SI_TIMER	SI_TIMER
  SI_QUEUE,			/* Sent by sigqueue.  */
# define SI_QUEUE	SI_QUEUE
  SI_USER,			/* Sent by kill, sigsend, raise.  */
# define SI_USER	SI_USER
  SI_KERNEL = 0x80		/* Send by kernel.  */
#define SI_KERNEL	SI_KERNEL
};


/* `si_code' values for SIGILL signal.  */
enum {
  ILL_ILLOPC = 1,		/* Illegal opcode.  */
# define ILL_ILLOPC	ILL_ILLOPC
  ILL_ILLOPN,			/* Illegal operand.  */
# define ILL_ILLOPN	ILL_ILLOPN
  ILL_ILLADR,			/* Illegal addressing mode.  */
# define ILL_ILLADR	ILL_ILLADR
  ILL_ILLTRP,			/* Illegal trap. */
# define ILL_ILLTRP	ILL_ILLTRP
  ILL_PRVOPC,			/* Privileged opcode.  */
# define ILL_PRVOPC	ILL_PRVOPC
  ILL_PRVREG,			/* Privileged register.  */
# define ILL_PRVREG	ILL_PRVREG
  ILL_COPROC,			/* Coprocessor error.  */
# define ILL_COPROC	ILL_COPROC
  ILL_BADSTK			/* Internal stack error.  */
# define ILL_BADSTK	ILL_BADSTK
};

/* `si_code' values for SIGFPE signal.  */
enum {
  FPE_INTDIV = 1,		/* Integer divide by zero.  */
# define FPE_INTDIV	FPE_INTDIV
  FPE_INTOVF,			/* Integer overflow.  */
# define FPE_INTOVF	FPE_INTOVF
  FPE_FLTDIV,			/* Floating point divide by zero.  */
# define FPE_FLTDIV	FPE_FLTDIV
  FPE_FLTOVF,			/* Floating point overflow.  */
# define FPE_FLTOVF	FPE_FLTOVF
  FPE_FLTUND,			/* Floating point underflow.  */
# define FPE_FLTUND	FPE_FLTUND
  FPE_FLTRES,			/* Floating point inexact result.  */
# define FPE_FLTRES	FPE_FLTRES
  FPE_FLTINV,			/* Floating point invalid operation.  */
# define FPE_FLTINV	FPE_FLTINV
  FPE_FLTSUB			/* Subscript out of range.  */
# define FPE_FLTSUB	FPE_FLTSUB
};

/* `si_code' values for SIGSEGV signal.  */
enum {
  SEGV_MAPERR = 1,		/* Address not mapped to object.  */
# define SEGV_MAPERR	SEGV_MAPERR
  SEGV_ACCERR			/* Invalid permissions for mapped object.  */
# define SEGV_ACCERR	SEGV_ACCERR
};

/* `si_code' values for SIGBUS signal.  */
enum {
  BUS_ADRALN = 1,		/* Invalid address alignment.  */
# define BUS_ADRALN	BUS_ADRALN
  BUS_ADRERR,			/* Non-existant physical address.  */
# define BUS_ADRERR	BUS_ADRERR
  BUS_OBJERR			/* Object specific hardware error.  */
# define BUS_OBJERR	BUS_OBJERR
};

/* `si_code' values for SIGTRAP signal.  */
enum {
  TRAP_BRKPT = 1,		/* Process breakpoint.  */
# define TRAP_BRKPT	TRAP_BRKPT
  TRAP_TRACE			/* Process trace trap.  */
# define TRAP_TRACE	TRAP_TRACE
};

/* `si_code' values for SIGCHLD signal.  */
enum {
  CLD_EXITED = 1,		/* Child has exited.  */
# define CLD_EXITED	CLD_EXITED
  CLD_KILLED,			/* Child was killed.  */
# define CLD_KILLED	CLD_KILLED
  CLD_DUMPED,			/* Child terminated abnormally.  */
# define CLD_DUMPED	CLD_DUMPED
  CLD_TRAPPED,			/* Traced child has trapped.  */
# define CLD_TRAPPED	CLD_TRAPPED
  CLD_STOPPED,			/* Child has stopped.  */
# define CLD_STOPPED	CLD_STOPPED
  CLD_CONTINUED			/* Stopped child has continued.  */
# define CLD_CONTINUED	CLD_CONTINUED
};

/* `si_code' values for SIGPOLL signal.  */
enum {
  POLL_IN = 1,			/* Data input available.  */
# define POLL_IN	POLL_IN
  POLL_OUT,			/* Output buffers available.  */
# define POLL_OUT	POLL_OUT
  POLL_MSG,			/* Input message available.   */
# define POLL_MSG	POLL_MSG
  POLL_ERR,			/* I/O error.  */
# define POLL_ERR	POLL_ERR
  POLL_PRI,			/* High priority input available.  */
# define POLL_PRI	POLL_PRI
  POLL_HUP			/* Device disconnected.  */
# define POLL_HUP	POLL_HUP
};

#define _NSIG_WORDS	((_NSIG/sizeof(long))>>3)

typedef struct {
  unsigned long sig[_NSIG_WORDS];
} sigset_t;

struct sigaction {
#if defined(__alpha__) || defined(__ia64__) || defined(__hppa__)
  union {
    sighandler_t _sa_handler;
    void (*_sa_sigaction)(int, siginfo_t*, void*);
  } _u;
  unsigned long sa_flags;
  sigset_t sa_mask;
#elif defined(__mips__)
  unsigned long sa_flags;
  union {
    sighandler_t _sa_handler;
    void (*_sa_sigaction)(int, siginfo_t*, void*);
  } _u;
  sigset_t sa_mask;
  void (*sa_restorer)(void);
  int32_t sa_resv[1];
#else	/* arm, i386, ppc, s390, sparc, saprc64, x86_64 */
  union {
    sighandler_t _sa_handler;
    void (*_sa_sigaction)(int, siginfo_t*, void*);
  } _u;
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  sigset_t sa_mask;
#endif
};

#define sa_handler	_u._sa_handler
#define sa_sigaction	_u._sa_sigaction


#define SIGEV_SIGNAL    0       /* notify via signal */
#define SIGEV_NONE      1       /* other notification: meaningless */
#define SIGEV_THREAD    2       /* deliver via thread creation */
#define SIGEV_THREAD_ID 4       /* deliver to thread */

#define SIGEV_MAX_SIZE  64
#ifndef SIGEV_PAD_SIZE
#define SIGEV_PAD_SIZE  ((SIGEV_MAX_SIZE/sizeof(int32_t)) - 3)
#endif

typedef struct sigevent {
  sigval_t sigev_value;
  int32_t sigev_signo;
  int32_t sigev_notify;
  union {
    int32_t _pad[SIGEV_PAD_SIZE];
    int32_t _tid;

    struct {
      void(*_function)(sigval_t);
      void*_attribute; /* really pthread_attr_t */
    } _sigev_thread;
  } _sigev_un;
} sigevent_t;

#define sigev_notify_function   _sigev_un._sigev_thread._function
#define sigev_notify_attributes _sigev_un._sigev_thread._attribute
#define sigev_notify_thread_id  _sigev_un._tid

typedef struct sigaltstack {
#if defined(__mips__)
  void *ss_sp;
  size_t ss_size;
  int32_t ss_flags;
#else
  void *ss_sp;
  int32_t ss_flags;
  size_t ss_size;
#endif
} stack_t;

int sigaltstack(const struct sigaltstack *newstack, struct sigaltstack *oldstack) __THROW;

int sigemptyset(sigset_t *set) __THROW;
int sigfillset(sigset_t *set) __THROW;
int sigaddset(sigset_t *set, int signum) __THROW;
int sigdelset(sigset_t *set, int signum) __THROW;
int sigismember(const sigset_t *set, int signo) __THROW;
int sigsuspend(const sigset_t *mask) __THROW;
int sigpending(sigset_t *set) __THROW;
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) __THROW;

#ifdef _GNU_SOURCE
int sigisemptyset(const sigset_t *set) __THROW __pure;
int sigorset(sigset_t *set, const sigset_t *left, const sigset_t *right) __THROW;
int sigandset(sigset_t *set, const sigset_t *left, const sigset_t *right) __THROW;
#endif

sighandler_t signal(int signum, sighandler_t action);

int raise (int sig) __THROW;
int kill(pid_t pid, int sig) __THROW;

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) __THROW;

#include <sys/time.h>

int sigtimedwait(const sigset_t *mask, siginfo_t *info, const struct timespec *ts) __THROW;
int sigqueueinfo(pid_t pid, int sig, siginfo_t *info) __THROW;
int siginterrupt(int sig, int flag) __THROW;

int killpg(pid_t pgrp, int sig) __THROW;

/* 0 is OK ! kernel puts in MAX_THREAD_TIMEOUT :) */
#define sigwaitinfo(m, i) sigtimedwait((m),(i),0)

int sigwait(const sigset_t* set,int* sig) __THROW;

extern const char *const* sys_siglist;

#include <sys/ucontext.h>

__END_DECLS

#endif
