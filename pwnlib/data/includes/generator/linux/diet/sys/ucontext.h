#ifndef _SYS_UCONTEXT_H
#define _SYS_UCONTEXT_H

#include <asm/sigcontext.h>
#include <signal.h>

__BEGIN_DECLS

#if !defined(__sparc__) && !defined(__sparc64__)
typedef struct sigcontext mcontext_t;
#endif

#if defined(__i386__) || defined(__arm__) || defined(__mips__) || defined(__mips64__) || defined(__powerpc__) || defined(__powerpc64__) || defined(__hppa__)
struct ucontext {
  unsigned long		uc_flags;
  struct ucontext	*uc_link;
  stack_t		uc_stack;
  struct sigcontext	uc_mcontext;
  sigset_t		uc_sigmask;	/* mask last for extensibility */
};
#elif defined(__alpha__)
struct ucontext {
  unsigned long		uc_flags;
  struct ucontext	*uc_link;
  unsigned long		uc_osf_sigmask;
  stack_t		uc_stack;
  struct sigcontext	uc_mcontext;
  sigset_t		uc_sigmask;	/* mask last for extensibility */
};
#elif defined(__sparc__) || defined(__sparc64__)

#define MC_TSTATE	0
#define MC_PC		1
#define MC_NPC		2
#define MC_Y		3
#define MC_G1		4
#define MC_G2		5
#define MC_G3		6
#define MC_G4		7
#define MC_G5		8
#define MC_G6		9
#define MC_G7		10
#define MC_O0		11
#define MC_O1		12
#define MC_O2		13
#define MC_O3		14
#define MC_O4		15
#define MC_O5		16
#define MC_O6		17
#define MC_O7		18
#define MC_NGREG	19

typedef unsigned long mc_greg_t;
typedef mc_greg_t mc_gregset_t[MC_NGREG];

#define MC_MAXFPQ	16
struct mc_fq {
  unsigned long		*mcfq_addr;
  unsigned int		mcfq_insn;
};

typedef struct mc_fpu {
  union {
    unsigned int	sregs[32];
    unsigned long	dregs[32];
    long double		qregs[16];
  } mcfpu_fregs;
  unsigned long		mcfpu_fsr;
  unsigned long		mcfpu_fprs;
  unsigned long		mcfpu_gsr;
  struct mc_fq		*mcfpu_fq;
  unsigned char		mcfpu_qcnt;
  unsigned char		mcfpu_qentsz;
  unsigned char		mcfpu_enab;
} mc_fpu_t;

typedef struct {
  mc_gregset_t	mc_gregs;
  mc_greg_t	mc_fp;
  mc_greg_t	mc_i7;
  mc_fpu_t	mc_fpregs;
} mcontext_t;

struct ucontext {
  struct ucontext         *uc_link;
  unsigned long           uc_flags;
  sigset_t                uc_sigmask;
  mcontext_t              uc_mcontext;
};
#elif defined(__s390__)
struct ucontext {
  unsigned long		uc_flags;
  struct ucontext	*uc_link;
  stack_t		uc_stack;
  _sigregs		uc_mcontext;
  sigset_t		uc_sigmask;	/* mask last for extensibility */
};
#elif defined(__ia64__)

/* oh my god is this ugly!  --fefe*/
struct ucontext {
  struct sigcontext uc_mcontext;
};

#define uc_link		uc_mcontext.sc_gr[0]	/* wrong type; nobody cares */
#define uc_sigmask	uc_mcontext.sc_sigmask
#define uc_stack	uc_mcontext.sc_stack
#elif defined(__x86_64__)

struct ucontext {
	unsigned long	  uc_flags;
	struct ucontext  *uc_link;
	stack_t		  uc_stack;
	struct sigcontext uc_mcontext;
	sigset_t	  uc_sigmask;	/* mask last for extensibility */
};

#else
#error NEED TO PORT <sys/sigcontext.h>!
#endif

typedef struct ucontext ucontext_t;

__END_DECLS

#endif
