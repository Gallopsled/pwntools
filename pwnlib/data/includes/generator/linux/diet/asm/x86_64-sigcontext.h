#include <asm/types.h>

/* FXSAVE frame */
/* Note: reserved1/2 may someday contain valuable data. Always save/restore
   them when you change signal frames. */
struct _fpstate {
	__u16	cwd;
	__u16	swd;
	__u16	twd;	/* Note this is not the same as the 32bit/x87/FSAVE twd */
	__u16	fop;
	__u64	rip;
	__u64	rdp;
	__u32	mxcsr;
	__u32	mxcsr_mask;
	__u32	st_space[32];	/* 8*16 bytes for each FP-reg */
	__u32	xmm_space[64];	/* 16*16 bytes for each XMM-reg  */
	__u32	reserved2[24];
};

struct sigcontext { 		// ofs	ofs-x32
	unsigned long r8;	// 0	0
	unsigned long r9;	// 8	4
	unsigned long r10;	// 16	8
	unsigned long r11;	// 24	12
	unsigned long r12;	// 32	16
	unsigned long r13;	// 40	20
	unsigned long r14;	// 48	24
	unsigned long r15;	// 56	28
	unsigned long rdi;	// 64	32
	unsigned long rsi;	// 72	36
	unsigned long rbp;	// 80	40
	unsigned long rbx;	// 88	44
	unsigned long rdx;	// 96	48
	unsigned long rax;	// 104	52
	unsigned long rcx;	// 112	56
	unsigned long rsp;	// 120	60
	unsigned long rip;	// 128	64
	unsigned long eflags;	// 136	68
	__u16         cs;	// 144	72
	__u16         gs;	// 146	74
	__u16         fs;	// 148	76
	__u16         __pad0;
	unsigned long err;	// 152	80
	unsigned long trapno;	// 160	84
	unsigned long oldmask;	// 168	88
	unsigned long cr2;	// 176	92
	struct _fpstate *fpstate;	/* zero when no FPU context */
	unsigned long reserved1[8];
};
