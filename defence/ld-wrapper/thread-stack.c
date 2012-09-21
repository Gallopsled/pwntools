#include <sys/mman.h>
#include <stdlib.h>
#include "thread-stack.h"

static __thread void* local_thread_stack = NULL;

void** thread_stack() {
    if(local_thread_stack == NULL) {
        local_thread_stack = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    return &local_thread_stack;
}


