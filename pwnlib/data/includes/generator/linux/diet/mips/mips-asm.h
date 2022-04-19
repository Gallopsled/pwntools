#ifndef DIET_MIPS_ASM_H
#define DIET_MIPS_ASM_H

#ifdef __ASSEMBLER__
#if _MIPS_SIM == _ABI64

#define PTR_LA    dla
#define PTR_SW    sd
#define PTR_LL    lld
#define PTR_SC    scd
#define PTR_LW    ld
#define PTR_SLL   dsll
#define PTR_ADD   dadd

#else

#define PTR_LA    la
#define PTR_SW    sw
#define PTR_LL    ll
#define PTR_SC    sc
#define PTR_LW    lw
#define PTR_SLL   sll
#define PTR_ADD   add

#endif
#endif /* __ASSEMBLER__ */

#endif /* DIET_MIPS_ASM_H */
