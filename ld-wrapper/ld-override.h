#ifndef __LD_OVERRIDE
#define __LD_OVERRIDE

#include <stdint.h>
#include <stdlib.h>

struct _override {
    void* function_addr;
    void* wrapper_addr;
    char *function_name;
};


#define constructor __attribute__((constructor))


#ifdef __i386__
#define WRAP(FUNCTION) \
    struct _override _##FUNCTION##_override = { NULL, (void*) FUNCTION##_wrapper, #FUNCTION }; \
    extern void FUNCTION (); \
    __asm(".text\r\n" \
          ".globl " #FUNCTION "\r\n" \
          ".type  " #FUNCTION ", @function\r\n" \
          #FUNCTION ":\r\n" \
            "push $_" #FUNCTION "_override\r\n" \
            "jmp wrapper" \
    )

#else
#define WRAP(FUNCTION) \
    struct _override _##FUNCTION##_override = { NULL, (void*) FUNCTION##_wrapper, #FUNCTION }; \
    extern void FUNCTION (); \
    __asm(".text\r\n" \
          ".globl " #FUNCTION "\r\n" \
          ".type  " #FUNCTION ", @function\r\n" \
          #FUNCTION ":\r\n" \
            "movabs $_" #FUNCTION "_override, %r11\r\n" \
            "push %r11\r\n" \
            "movabs $wrapper, %r11\r\n" \
            "jmp *%r11\r\n" \
    )
#endif

struct _save_state {
#ifdef __i386__
    uintptr_t ebx, ebp, edi, esi, esp;
    struct _override *function_override;
    uintptr_t eip;
#else
    uintptr_t rax, rbx, rcx, rdx, rbp, rdi, rsi, r8, r9, r10, r12, r13, r14, r15, rsp;
    struct _override *function_override;
    uintptr_t rip;
#endif
};

void wrapper();
void skip_real(uintptr_t retval);
void lookup_function(struct _override *function);
void consistency_check(struct _save_state *state);

#endif
