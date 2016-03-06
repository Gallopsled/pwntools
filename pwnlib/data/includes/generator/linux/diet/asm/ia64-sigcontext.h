#include <sys/ptrace.h>

#define PC(ctx) (ctx.sc_ip)

struct sigcontext {
	unsigned long		sc_flags;
	unsigned long		sc_nat;
	stack_t			sc_stack;
	unsigned long		sc_ip;
	unsigned long		sc_cfm;
	unsigned long		sc_um;
	unsigned long		sc_ar_rsc;
	unsigned long		sc_ar_bsp;
	unsigned long		sc_ar_rnat;
	unsigned long		sc_ar_ccv;
	unsigned long		sc_ar_unat;
	unsigned long		sc_ar_fpsr;
	unsigned long		sc_ar_pfs;
	unsigned long		sc_ar_lc;
	unsigned long		sc_pr;
	unsigned long		sc_br[8];
	unsigned long		sc_gr[32];
	struct ia64_fpreg	sc_fr[128];
	sigset_t		sc_mask;
};
