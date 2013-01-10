#include <sys/mman.h>
#include <stdlib.h>
#include "thread-stack.h"

static __thread char pwn_thread_stack_values[4096];
static __thread void* pwn_thread_stack_pointer = NULL;

void** pwn_thread_stack() {
    if(pwn_thread_stack_pointer == NULL)
        pwn_thread_stack_pointer = &pwn_thread_stack_values[4096];
    return &pwn_thread_stack_pointer;
}
