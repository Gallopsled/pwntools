#ifndef _SYS_PTRACE_H
#define _SYS_PTRACE_H

#include <sys/cdefs.h>
#include <inttypes.h>

__BEGIN_DECLS

#define PTRACE_TRACEME		   0
#define PTRACE_PEEKTEXT		   1
#define PTRACE_PEEKDATA		   2
#define PTRACE_PEEKUSR		   3
#define PTRACE_PEEKUSER		   PTRACE_PEEKUSR
#define PTRACE_POKETEXT		   4
#define PTRACE_POKEDATA		   5
#define PTRACE_POKEUSR		   6
#define PTRACE_POKEUSER		   PTRACE_POKEUSR
#define PTRACE_CONT		   7
#define PTRACE_KILL		   8
#define PTRACE_SINGLESTEP	   9

#define PTRACE_ATTACH		0x10
#define PTRACE_DETACH		0x11

#define PTRACE_SYSCALL		  24

/* 0x4200-0x4300 are reserved for architecture-independent additions.  */
/* #define PTRACE_SETOPTIONS	0x4200 */
#define PTRACE_GETEVENTMSG	0x4201
#define PTRACE_GETSIGINFO	0x4202
#define PTRACE_SETSIGINFO	0x4203

/* options set using PTRACE_SETOPTIONS */
#define PTRACE_O_TRACESYSGOOD	0x00000001
#define PTRACE_O_TRACEFORK	0x00000002
#define PTRACE_O_TRACEVFORK	0x00000004
#define PTRACE_O_TRACECLONE	0x00000008
#define PTRACE_O_TRACEEXEC	0x00000010
#define PTRACE_O_TRACEVFORKDONE	0x00000020
#define PTRACE_O_TRACEEXIT	0x00000040

#define PTRACE_O_MASK		0x0000007f

/* Wait extended result codes for the above trace options.  */
#define PTRACE_EVENT_FORK	1
#define PTRACE_EVENT_VFORK	2
#define PTRACE_EVENT_CLONE	3
#define PTRACE_EVENT_EXEC	4
#define PTRACE_EVENT_VFORK_DONE	5
#define PTRACE_EVENT_EXIT	6

#define PT_TRACE_ME		PTRACE_TRACEME
#define PT_READ_I		PTRACE_PEEKTEXT
#define PT_READ_D		PTRACE_PEEKDATA
#define PT_READ_U		PTRACE_PEEKUSER
#define PT_WRITE_I		PTRACE_POKETEXT
#define PT_WRITE_D		PTRACE_POKEDATA
#define PT_WRITE_U		PTRACE_POKEUSER
#define PT_CONTINUE		PTRACE_CONT
#define PT_KILL			PTRACE_KILL
#define PT_STEP			PTRACE_SINGLESTEP
#define PT_GETREGS		PTRACE_GETREGS
#define PT_SETREGS		PTRACE_SETREGS
#define PT_GETFPREGS		PTRACE_GETFPREGS
#define PT_SETFPREGS		PTRACE_SETFPREGS
#define PT_ATTACH		PTRACE_ATTACH
#define PT_DETACH		PTRACE_DETACH

#if defined(__i386__)
#define EBX 0
#define ECX 1
#define EDX 2
#define ESI 3
#define EDI 4
#define EBP 5
#define EAX 6
#define DS 7
#define ES 8
#define FS 9
#define GS 10
#define ORIG_EAX 11
#define EIP 12
#define CS  13
#define EFL 14
#define UESP 15
#define SS   16
#define FRAME_SIZE 17

/* this struct defines the way the registers are stored on the
   stack during a system call. */

struct pt_regs {
  long ebx;
  long ecx;
  long edx;
  long esi;
  long edi;
  long ebp;
  long eax;
  int32_t xds;
  int32_t xes;
  long orig_eax;
  long eip;
  int32_t xcs;
  long eflags;
  long esp;
  int32_t xss;
};

/* Arbitrarily choose the same ptrace numbers as used by the Sparc code. */
#define PTRACE_GETREGS            12
#define PTRACE_SETREGS            13
#define PTRACE_GETFPREGS          14
#define PTRACE_SETFPREGS          15
#define PTRACE_GETFPXREGS         18
#define PTRACE_SETFPXREGS         19

#define PTRACE_SETOPTIONS         21

/* options set using PTRACE_SETOPTIONS */
#define PTRACE_O_TRACESYSGOOD     0x00000001

#elif defined(__x86_64__)

struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* arguments: non interrupts/non tracing syscalls only save upto here*/
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
/* end of arguments */
/* cpu exception frame or undefined */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
/* top of stack page */
};

#elif defined(__s390__)

#define PT_PSWMASK  0x00
#define PT_PSWADDR  0x04
#define PT_GPR0     0x08
#define PT_GPR1     0x0C
#define PT_GPR2     0x10
#define PT_GPR3     0x14
#define PT_GPR4     0x18
#define PT_GPR5     0x1C
#define PT_GPR6     0x20
#define PT_GPR7     0x24
#define PT_GPR8     0x28
#define PT_GPR9     0x2C
#define PT_GPR10    0x30
#define PT_GPR11    0x34
#define PT_GPR12    0x38
#define PT_GPR13    0x3C
#define PT_GPR14    0x40
#define PT_GPR15    0x44
#define PT_ACR0     0x48
#define PT_ACR1     0x4C
#define PT_ACR2     0x50
#define PT_ACR3     0x54
#define PT_ACR4	    0x58
#define PT_ACR5	    0x5C
#define PT_ACR6	    0x60
#define PT_ACR7	    0x64
#define PT_ACR8	    0x68
#define PT_ACR9	    0x6C
#define PT_ACR10    0x70
#define PT_ACR11    0x74
#define PT_ACR12    0x78
#define PT_ACR13    0x7C
#define PT_ACR14    0x80
#define PT_ACR15    0x84
#define PT_ORIGGPR2 0x88
#define PT_FPC	    0x90
#define PT_FPR0_HI  0x98
#define PT_FPR0_LO  0x9C
#define PT_FPR1_HI  0xA0
#define PT_FPR1_LO  0xA4
#define PT_FPR2_HI  0xA8
#define PT_FPR2_LO  0xAC
#define PT_FPR3_HI  0xB0
#define PT_FPR3_LO  0xB4
#define PT_FPR4_HI  0xB8
#define PT_FPR4_LO  0xBC
#define PT_FPR5_HI  0xC0
#define PT_FPR5_LO  0xC4
#define PT_FPR6_HI  0xC8
#define PT_FPR6_LO  0xCC
#define PT_FPR7_HI  0xD0
#define PT_FPR7_LO  0xD4
#define PT_FPR8_HI  0xD8
#define PT_FPR8_LO  0XDC
#define PT_FPR9_HI  0xE0
#define PT_FPR9_LO  0xE4
#define PT_FPR10_HI 0xE8
#define PT_FPR10_LO 0xEC
#define PT_FPR11_HI 0xF0
#define PT_FPR11_LO 0xF4
#define PT_FPR12_HI 0xF8
#define PT_FPR12_LO 0xFC
#define PT_FPR13_HI 0x100
#define PT_FPR13_LO 0x104
#define PT_FPR14_HI 0x108
#define PT_FPR14_LO 0x10C
#define PT_FPR15_HI 0x110
#define PT_FPR15_LO 0x114
#define PT_CR_9	    0x118
#define PT_CR_10    0x11C
#define PT_CR_11    0x120
#define PT_IEEE_IP  0x13C
#define PT_LASTOFF  PT_IEEE_IP
#define PT_ENDREGS  0x140-1

#define NUM_GPRS	16
#define NUM_FPRS	16
#define NUM_CRS		16
#define NUM_ACRS	16
#define GPR_SIZE	4
#define FPR_SIZE	8
#define FPC_SIZE	4
#define FPC_PAD_SIZE	4 /* gcc insists on aligning the fpregs */
#define CR_SIZE		4
#define ACR_SIZE	4

#define STACK_FRAME_OVERHEAD	96	/* size of minimum stack frame */

/* this typedef defines how a Program Status Word looks like */
typedef struct {
        uint32_t   mask;
        uint32_t   addr;
} psw_t __attribute__ ((__aligned__(8)));

typedef union
{
	float   f;
	double  d;
        uint64_t   ui;
	struct
	{
		uint32_t hi;
		uint32_t lo;
	} fp;
} freg_t;

typedef struct
{
	uint32_t   fpc;
	freg_t  fprs[NUM_FPRS];
} s390_fp_regs;

#define FPC_EXCEPTION_MASK      0xF8000000
#define FPC_FLAGS_MASK          0x00F80000
#define FPC_DXC_MASK            0x0000FF00
#define FPC_RM_MASK             0x00000003
#define FPC_VALID_MASK          0xF8F8FF03

typedef struct
{
	psw_t psw;
	uint32_t gprs[NUM_GPRS];
	uint32_t acrs[NUM_ACRS];
	uint32_t orig_gpr2;
} s390_regs;

struct pt_regs
{
	psw_t psw;
	uint32_t gprs[NUM_GPRS];
	uint32_t acrs[NUM_ACRS];
	uint32_t orig_gpr2;
	uint32_t trap;
        uint32_t old_ilc;
};

typedef struct
{
	uint32_t cr[3];
} per_cr_words  __attribute__((__packed__));

#define PER_EM_MASK 0xE8000000

typedef uint32_t addr_t;

typedef	struct
{
	uint32_t em_branching          : 1;
	uint32_t em_instruction_fetch  : 1;
	/*
	 * Switching on storage alteration automatically fixes
	 * the storage alteration event bit in the users std.
	 */
	uint32_t em_storage_alteration : 1;
	uint32_t em_gpr_alt_unused     : 1;
	uint32_t em_store_real_address : 1;
	uint32_t                       : 3;
	uint32_t branch_addr_ctl       : 1;
	uint32_t                       : 1;
	uint32_t storage_alt_space_ctl : 1;
	uint32_t                       : 21;
	addr_t   starting_addr;
	addr_t   ending_addr;
} per_cr_bits  __attribute__((__packed__));

typedef struct
{
	uint16_t          perc_atmid;          /* 0x096 */
	uint32_t          address;             /* 0x098 */
	uint8_t           access_id;           /* 0x0a1 */
} per_lowcore_words  __attribute__((__packed__));

typedef struct
{
	uint32_t perc_branching          : 1; /* 0x096 */
	uint32_t perc_instruction_fetch  : 1;
	uint32_t perc_storage_alteration : 1;
	uint32_t perc_gpr_alt_unused     : 1;
	uint32_t perc_store_real_address : 1;
	uint32_t                         : 4;
	uint32_t atmid_validity_bit      : 1;
	uint32_t atmid_psw_bit_32        : 1;
	uint32_t atmid_psw_bit_5         : 1;
	uint32_t atmid_psw_bit_16        : 1;
	uint32_t atmid_psw_bit_17        : 1;
	uint32_t si                      : 2;
	addr_t   address;                     /* 0x098 */
	uint32_t                         : 4; /* 0x0a1 */
	uint32_t access_id               : 4;
} per_lowcore_bits __attribute__((__packed__));

typedef struct
{
	union {
		per_cr_words   words;
		per_cr_bits    bits;
	} control_regs  __attribute__((__packed__));
	/*
	 * Use these flags instead of setting em_instruction_fetch
	 * directly they are used so that single stepping can be
	 * switched on & off while not affecting other tracing
	 */
	uint32_t  single_step       : 1;
	uint32_t  instruction_fetch : 1;
	uint32_t                    : 30;
	/*
	 * These addresses are copied into cr10 & cr11 if single
	 * stepping is switched off
	 */
	uint32_t     starting_addr;
	uint32_t     ending_addr;
	union {
		per_lowcore_words words;
		per_lowcore_bits  bits;
	} lowcore;
} per_struct __attribute__((__packed__));

typedef struct
{
	uint32_t  len;
	addr_t kernel_addr;
	addr_t process_addr;
} ptrace_area;

/*
 * S/390 specific non posix ptrace requests. I chose unusual values so
 * they are unlikely to clash with future ptrace definitions.
 */
#define PTRACE_PEEKUSR_AREA           0x5000
#define PTRACE_POKEUSR_AREA           0x5001
#define PTRACE_PEEKTEXT_AREA	      0x5002
#define PTRACE_PEEKDATA_AREA	      0x5003
#define PTRACE_POKETEXT_AREA	      0x5004
#define PTRACE_POKEDATA_AREA 	      0x5005
/*
 * PT_PROT definition is loosely based on hppa bsd definition in
 * gdb/hppab-nat.c
 */
#define PTRACE_PROT                       21

typedef enum
{
	ptprot_set_access_watchpoint,
	ptprot_set_write_watchpoint,
	ptprot_disable_watchpoint
} ptprot_flags;

typedef struct
{
	addr_t           lowaddr;
	addr_t           hiaddr;
	ptprot_flags     prot;
} ptprot_area;

/* Sequence of bytes for breakpoint illegal instruction.  */
#define S390_BREAKPOINT     {0x0,0x1}
#define S390_BREAKPOINT_U16 ((uint16_t)0x0001)
#define S390_SYSCALL_OPCODE ((uint16_t)0x0a00)
#define S390_SYSCALL_SIZE   2

/*
 * The user_regs_struct defines the way the user registers are
 * store on the stack for signal handling.
 */
struct user_regs_struct
{
	psw_t psw;
	uint32_t gprs[NUM_GPRS];
	uint32_t acrs[NUM_ACRS];
	uint32_t orig_gpr2;
	s390_fp_regs fp_regs;
	/*
	 * These per registers are in here so that gdb can modify them
	 * itself as there is no "official" ptrace interface for hardware
	 * watchpoints. This is the way intel does it.
	 */
	per_struct per_info;
	addr_t  ieee_instruction_pointer;
	/* Used to give failing instruction back to user for ieee exceptions */
};

#elif defined(__arm__)

/* this assumes armv */
#define USR26_MODE	0x00
#define FIQ26_MODE	0x01
#define IRQ26_MODE	0x02
#define SVC26_MODE	0x03
#define USR_MODE	0x10
#define FIQ_MODE	0x11
#define IRQ_MODE	0x12
#define SVC_MODE	0x13
#define ABT_MODE	0x17
#define UND_MODE	0x1b
#define SYSTEM_MODE	0x1f
#define MODE_MASK	0x1f
#define T_BIT		0x20
#define F_BIT		0x40
#define I_BIT		0x80
#define CC_V_BIT	(1 << 28)
#define CC_C_BIT	(1 << 29)
#define CC_Z_BIT	(1 << 30)
#define CC_N_BIT	(1 << 31)
#define PCMASK		0

struct pt_regs {
	long uregs[18];
};

#define ARM_cpsr	uregs[16]
#define ARM_pc		uregs[15]
#define ARM_lr		uregs[14]
#define ARM_sp		uregs[13]
#define ARM_ip		uregs[12]
#define ARM_fp		uregs[11]
#define ARM_r10		uregs[10]
#define ARM_r9		uregs[9]
#define ARM_r8		uregs[8]
#define ARM_r7		uregs[7]
#define ARM_r6		uregs[6]
#define ARM_r5		uregs[5]
#define ARM_r4		uregs[4]
#define ARM_r3		uregs[3]
#define ARM_r2		uregs[2]
#define ARM_r1		uregs[1]
#define ARM_r0		uregs[0]
#define ARM_ORIG_r0	uregs[17]

#elif defined(__alpha__)

struct pt_regs {
  unsigned long r0;
  unsigned long r1;
  unsigned long r2;
  unsigned long r3;
  unsigned long r4;
  unsigned long r5;
  unsigned long r6;
  unsigned long r7;
  unsigned long r8;
  unsigned long r19;
  unsigned long r20;
  unsigned long r21;
  unsigned long r22;
  unsigned long r23;
  unsigned long r24;
  unsigned long r25;
  unsigned long r26;
  unsigned long r27;
  unsigned long r28;
  unsigned long hae;
/* JRP - These are the values provided to a0-a2 by PALcode */
  unsigned long trap_a0;
  unsigned long trap_a1;
  unsigned long trap_a2;
/* These are saved by PAL-code: */
  unsigned long ps;
  unsigned long pc;
  unsigned long gp;
  unsigned long r16;
  unsigned long r17;
  unsigned long r18;
};

struct switch_stack {
  unsigned long r9;
  unsigned long r10;
  unsigned long r11;
  unsigned long r12;
  unsigned long r13;
  unsigned long r14;
  unsigned long r15;
  unsigned long r26;
  unsigned long fp[32];	/* fp[31] is fpcr */
};

#elif defined(__mips__)

/* 0 - 31 are integer registers, 32 - 63 are fp registers.  */
#define FPR_BASE	32
#define PC		64
#define CAUSE		65
#define BADVADDR	66
#define MMHI		67
#define MMLO		68
#define FPC_CSR		69
#define FPC_EIR		70

struct pt_regs {
  /* Pad bytes for argument save space on the stack. */
  unsigned long pad0[6];
  /* Saved main processor registers. */
  unsigned long regs[32];
  /* Other saved registers. */
  unsigned long lo;
  unsigned long hi;
  /* saved cp0 registers */
  unsigned long cp0_epc;
  unsigned long cp0_badvaddr;
  unsigned long cp0_status;
  unsigned long cp0_cause;
};

#elif defined(__sparc__)

struct pt_regs {
  unsigned long psr;
  unsigned long pc;
  unsigned long npc;
  unsigned long y;
  unsigned long u_regs[16]; /* globals and ins */
};

#define UREG_G0        0
#define UREG_G1        1
#define UREG_G2        2
#define UREG_G3        3
#define UREG_G4        4
#define UREG_G5        5
#define UREG_G6        6
#define UREG_G7        7
#define UREG_I0        8
#define UREG_I1        9
#define UREG_I2        10
#define UREG_I3        11
#define UREG_I4        12
#define UREG_I5        13
#define UREG_I6        14
#define UREG_I7        15
#define UREG_WIM       UREG_G0
#define UREG_FADDR     UREG_G0
#define UREG_FP        UREG_I6
#define UREG_RETPC     UREG_I7

/* A register window */
struct reg_window {
  unsigned long locals[8];
  unsigned long ins[8];
};

/* A Sparc stack frame */
struct sparc_stackf {
  unsigned long locals[8];
  unsigned long ins[6];
  struct sparc_stackf *fp;
  unsigned long callers_pc;
  char *structptr;
  unsigned long xargs[6];
  unsigned long xxargs[1];
};

#define TRACEREG_SZ   sizeof(struct pt_regs)
#define STACKFRAME_SZ sizeof(struct sparc_stackf)
#define REGWIN_SZ     sizeof(struct reg_window)

/* These are for pt_regs. */
#define PT_PSR    0x0
#define PT_PC     0x4
#define PT_NPC    0x8
#define PT_Y      0xc
#define PT_G0     0x10
#define PT_WIM    PT_G0
#define PT_G1     0x14
#define PT_G2     0x18
#define PT_G3     0x1c
#define PT_G4     0x20
#define PT_G5     0x24
#define PT_G6     0x28
#define PT_G7     0x2c
#define PT_I0     0x30
#define PT_I1     0x34
#define PT_I2     0x38
#define PT_I3     0x3c
#define PT_I4     0x40
#define PT_I5     0x44
#define PT_I6     0x48
#define PT_FP     PT_I6
#define PT_I7     0x4c

/* Reg_window offsets */
#define RW_L0     0x00
#define RW_L1     0x04
#define RW_L2     0x08
#define RW_L3     0x0c
#define RW_L4     0x10
#define RW_L5     0x14
#define RW_L6     0x18
#define RW_L7     0x1c
#define RW_I0     0x20
#define RW_I1     0x24
#define RW_I2     0x28
#define RW_I3     0x2c
#define RW_I4     0x30
#define RW_I5     0x34
#define RW_I6     0x38
#define RW_I7     0x3c

/* Stack_frame offsets */
#define SF_L0     0x00
#define SF_L1     0x04
#define SF_L2     0x08
#define SF_L3     0x0c
#define SF_L4     0x10
#define SF_L5     0x14
#define SF_L6     0x18
#define SF_L7     0x1c
#define SF_I0     0x20
#define SF_I1     0x24
#define SF_I2     0x28
#define SF_I3     0x2c
#define SF_I4     0x30
#define SF_I5     0x34
#define SF_FP     0x38
#define SF_PC     0x3c
#define SF_RETP   0x40
#define SF_XARG0  0x44
#define SF_XARG1  0x48
#define SF_XARG2  0x4c
#define SF_XARG3  0x50
#define SF_XARG4  0x54
#define SF_XARG5  0x58
#define SF_XXARG  0x5c

/* Stuff for the ptrace system call */
#define PTRACE_SUNATTACH	  10
#define PTRACE_SUNDETACH	  11
#define PTRACE_GETREGS            12
#define PTRACE_SETREGS            13
#define PTRACE_GETFPREGS          14
#define PTRACE_SETFPREGS          15
#define PTRACE_READDATA           16
#define PTRACE_WRITEDATA          17
#define PTRACE_READTEXT           18
#define PTRACE_WRITETEXT          19
#define PTRACE_GETFPAREGS         20
#define PTRACE_SETFPAREGS         21

#define PTRACE_GETUCODE           29  /* stupid bsd-ism */

#elif defined(__powerpc__) || defined (__powerpc64__)

#include <asm/sigcontext.h>

#elif defined(__hppa__)

#include <inttypes.h>

struct pt_regs {
	unsigned long gr[32];	/* PSW is in gr[0] */
	uint64_t fr[32];
	unsigned long sr[ 8];
	unsigned long iasq[2];
	unsigned long iaoq[2];
	unsigned long cr27;
	unsigned long pad0;     /* available for other uses */
	unsigned long orig_r28;
	unsigned long ksp;
	unsigned long kpc;
	unsigned long sar;	/* CR11 */
	unsigned long iir;	/* CR19 */
	unsigned long isr;	/* CR20 */
	unsigned long ior;	/* CR21 */
	unsigned long ipsw;	/* CR22 */
};

#define PTRACE_SINGLEBLOCK	12	/* resume execution until next branch */
#define PTRACE_GETSIGINFO	13	/* get child's siginfo structure */
#define PTRACE_SETSIGINFO	14	/* set child's siginfo structure */

#elif defined(__ia64__)

struct ia64_fpreg {
  union {
    unsigned long bits[2];
  } u;
} __attribute__ ((__aligned__ (16)));

struct pt_regs {
	unsigned long cr_ipsr;		/* interrupted task's psr */
	unsigned long cr_iip;		/* interrupted task's instruction pointer */
	unsigned long cr_ifs;		/* interrupted task's function state */
	unsigned long ar_unat;		/* interrupted task's NaT register (preserved) */
	unsigned long ar_pfs;		/* prev function state  */
	unsigned long ar_rsc;		/* RSE configuration */
	unsigned long ar_rnat;		/* RSE NaT */
	unsigned long ar_bspstore;	/* RSE bspstore */
	unsigned long pr;		/* 64 predicate registers (1 bit each) */
	unsigned long b6;		/* scratch */
	unsigned long loadrs;		/* size of dirty partition << 16 */
	unsigned long r1;		/* the gp pointer */
	unsigned long r2;		/* scratch */
	unsigned long r3;		/* scratch */
	unsigned long r12;		/* interrupted task's memory stack pointer */
	unsigned long r13;		/* thread pointer */
	unsigned long r14;		/* scratch */
	unsigned long r15;		/* scratch */
	unsigned long r8;		/* scratch (return value register 0) */
	unsigned long r9;		/* scratch (return value register 1) */
	unsigned long r10;		/* scratch (return value register 2) */
	unsigned long r11;		/* scratch (return value register 3) */
	unsigned long r16;		/* scratch */
	unsigned long r17;		/* scratch */
	unsigned long r18;		/* scratch */
	unsigned long r19;		/* scratch */
	unsigned long r20;		/* scratch */
	unsigned long r21;		/* scratch */
	unsigned long r22;		/* scratch */
	unsigned long r23;		/* scratch */
	unsigned long r24;		/* scratch */
	unsigned long r25;		/* scratch */
	unsigned long r26;		/* scratch */
	unsigned long r27;		/* scratch */
	unsigned long r28;		/* scratch */
	unsigned long r29;		/* scratch */
	unsigned long r30;		/* scratch */
	unsigned long r31;		/* scratch */
	unsigned long ar_ccv;		/* compare/exchange value (scratch) */
	unsigned long ar_fpsr;		/* floating point status (preserved) */
	unsigned long b0;		/* return pointer (bp) */
	unsigned long b7;		/* scratch */
	struct ia64_fpreg f6;		/* scratch */
	struct ia64_fpreg f7;		/* scratch */
	struct ia64_fpreg f8;		/* scratch */
	struct ia64_fpreg f9;		/* scratch */
};

struct switch_stack {
	unsigned long caller_unat;	/* user NaT collection register (preserved) */
	unsigned long ar_fpsr;		/* floating-point status register */

	struct ia64_fpreg f2;		/* preserved */
	struct ia64_fpreg f3;		/* preserved */
	struct ia64_fpreg f4;		/* preserved */
	struct ia64_fpreg f5;		/* preserved */

	struct ia64_fpreg f10;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f11;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f12;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f13;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f14;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f15;		/* scratch, but untouched by kernel */
	struct ia64_fpreg f16;		/* preserved */
	struct ia64_fpreg f17;		/* preserved */
	struct ia64_fpreg f18;		/* preserved */
	struct ia64_fpreg f19;		/* preserved */
	struct ia64_fpreg f20;		/* preserved */
	struct ia64_fpreg f21;		/* preserved */
	struct ia64_fpreg f22;		/* preserved */
	struct ia64_fpreg f23;		/* preserved */
	struct ia64_fpreg f24;		/* preserved */
	struct ia64_fpreg f25;		/* preserved */
	struct ia64_fpreg f26;		/* preserved */
	struct ia64_fpreg f27;		/* preserved */
	struct ia64_fpreg f28;		/* preserved */
	struct ia64_fpreg f29;		/* preserved */
	struct ia64_fpreg f30;		/* preserved */
	struct ia64_fpreg f31;		/* preserved */

	unsigned long r4;		/* preserved */
	unsigned long r5;		/* preserved */
	unsigned long r6;		/* preserved */
	unsigned long r7;		/* preserved */

	unsigned long b0;		/* so we can force a direct return in copy_thread */
	unsigned long b1;
	unsigned long b2;
	unsigned long b3;
	unsigned long b4;
	unsigned long b5;

	unsigned long ar_pfs;		/* previous function state */
	unsigned long ar_lc;		/* loop counter (preserved) */
	unsigned long ar_unat;		/* NaT bits for r4-r7 */
	unsigned long ar_rnat;		/* RSE NaT collection register */
	unsigned long ar_bspstore;	/* RSE dirty base (preserved) */
	unsigned long pr;		/* 64 predicate registers (1 bit each) */
};

#endif

extern long int ptrace(int request, ...) __THROW;

__END_DECLS

#endif
