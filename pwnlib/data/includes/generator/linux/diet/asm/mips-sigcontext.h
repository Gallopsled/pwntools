
/*
 * Keep this struct definition in sync with the sigcontext fragment
 * in arch/mips/tools/offset.c
 */
struct sigcontext {
	unsigned int       sc_regmask;		/* Unused */
	unsigned int       sc_status;
	unsigned long long sc_pc;
	unsigned long long sc_regs[32];
	unsigned long long sc_fpregs[32];	/* Unused */
	unsigned int       sc_ownedfp;
	unsigned int       sc_fpc_csr;		/* Unused */
	unsigned int       sc_fpc_eir;		/* Unused */
	unsigned int       sc_ssflags;		/* Unused */
	unsigned long long sc_mdhi;
	unsigned long long sc_mdlo;

	unsigned int       sc_cause;		/* Unused */
	unsigned int       sc_badvaddr;		/* Unused */

	unsigned long      sc_sigset[4];	/* kernel's sigset_t */
};
