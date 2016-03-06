#define __NUM_GPRS 16
#define __NUM_FPRS 16
#define __NUM_ACRS 16

/* Has to be at least _NSIG_WORDS from asm/signal.h */
#define _SIGCONTEXT_NSIG	64
#define _SIGCONTEXT_NSIG_BPW	64
/* Size of stack frame allocated when calling signal handler. */
#define __SIGNAL_FRAMESIZE	160

#define _SIGCONTEXT_NSIG_WORDS	(_SIGCONTEXT_NSIG / _SIGCONTEXT_NSIG_BPW)
#define _SIGMASK_COPY_SIZE	(sizeof(unsigned long)*_SIGCONTEXT_NSIG_WORDS)

typedef struct
{
        unsigned long mask;
        unsigned long addr;
} __attribute__ ((aligned(8))) _psw_t;

typedef struct
{
	_psw_t psw;
	unsigned long gprs[__NUM_GPRS];
	unsigned int  acrs[__NUM_ACRS];
} _s390_regs_common;

typedef struct
{
	unsigned int fpc;
	double   fprs[__NUM_FPRS];
} _s390_fp_regs;

typedef struct
{
	_s390_regs_common regs;
	_s390_fp_regs     fpregs;
} _sigregs;

struct sigcontext
{
	unsigned long	oldmask[_SIGCONTEXT_NSIG_WORDS];
	_sigregs        *sregs;
};
