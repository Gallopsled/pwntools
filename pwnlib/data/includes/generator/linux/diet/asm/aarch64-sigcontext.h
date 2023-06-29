struct sigcontext {
	unsigned long fault_address;
	/* AArch64 registers */
	unsigned long regs[31];
	unsigned long sp;
	unsigned long pc;
	unsigned long pstate;
	/* 4K reserved for FP/SIMD state and future expansion */
	unsigned char __reserved[4096] __attribute__((__aligned__(16)));
};
