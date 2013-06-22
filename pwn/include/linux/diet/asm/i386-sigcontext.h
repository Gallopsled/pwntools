#include <asm/types.h>

struct _fpreg {
	__u16          significand[4];
	__u16          exponent;
};

struct _fpxreg {
	__u16          significand[4];
	__u16          exponent;
	__u16          padding[3];
};

struct _xmmreg {
	unsigned long element[4];
};

struct _fpstate {
	/* Regular FPU environment */
	unsigned long 	cw;
	unsigned long	sw;
	unsigned long	tag;
	unsigned long	ipoff;
	unsigned long	cssel;
	unsigned long	dataoff;
	unsigned long	datasel;
	struct _fpreg	_st[8];
	__u16         	status;
	__u16         	magic;		/* 0xffff = regular FPU data only */

	/* FXSR FPU environment */
	unsigned long	_fxsr_env[6];	/* FXSR FPU env is ignored */
	unsigned long	mxcsr;
	unsigned long	reserved;
	struct _fpxreg	_fxsr_st[8];	/* FXSR FPU reg data is ignored */
	struct _xmmreg	_xmm[8];
	unsigned long	padding[56];
};

#define X86_FXSR_MAGIC		0x0000
#define PC(ctx) (ctx.eip)

struct sigcontext {
	__u16         gs, __gsh;
	__u16         fs, __fsh;
	__u16         es, __esh;
	__u16         ds, __dsh;
	unsigned long edi;
	unsigned long esi;
	unsigned long ebp;
	unsigned long esp;
	unsigned long ebx;
	unsigned long edx;
	unsigned long ecx;
	unsigned long eax;
	unsigned long trapno;
	unsigned long err;
	unsigned long eip;
	__u16         cs, __csh;
	unsigned long eflags;
	unsigned long esp_at_signal;
	__u16         ss, __ssh;
	struct _fpstate * fpstate;
	unsigned long oldmask;
	unsigned long cr2;
};

