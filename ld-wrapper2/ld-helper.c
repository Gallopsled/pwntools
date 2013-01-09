#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include "ld-override.h"

char *names[] = { "rand", "srand" };
int pwn_return;

#define PWN_RAND 0
#define PWN_SRAND 1

void pwn_lookup_function(struct save_state volatile state) {
    char *msg, *name;

    if(*state.function_cache != NULL) return;

    if(state.function_number >= sizeof(names) / sizeof(names[0])) {
        fprintf(stderr, "pwn_lookup_function called with too large a function number: 0x%08x\n", state.function_number);
        fflush(stderr);
        exit(1);
    }

    name = names[state.function_number];

    state.function_cache = dlsym(RTLD_NEXT, name);

    if ((msg = dlerror()) != NULL) {
        fputs("dlsym failed for symbol ", stderr);
        fputs(name, stderr);
        fputs(": ", stderr);
        fputs(msg, stderr);
        fflush(stderr);
        exit(1);
    }
}

int rand_count = 0;

int pwn_pre_handler(struct save_state state) {
    switch(state.function_number) {
        case PWN_RAND:
            if(rand_count++ == 10) {
                return PWN_ABORT(2);
                printf("AND NOW YOU DIE!!!\n");
            } else if(rand_count > 5) {
                return PWN_OVERRIDE(17);
            } else {
                return PWN_OK;
            }
    }
    return PWN_OK;
}

int pwn_post_handler(struct save_state state) {
    return 0;
}
