#include <stdint.h>
#include <stdlib.h>

struct save_state {
#ifdef __i386__
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax, flags, function_number;
    void **function_cache;
    uint32_t eip;
#else
#endif
};


#define PWN_NAME(state) (names[state.function_number])
#define PWN_OVERRIDE(n) (pwn_return = (n), (unsigned int) &pwn_return)
#define PWN_ABORT(n) ((n) & 0xff)
#define PWN_OK 0
