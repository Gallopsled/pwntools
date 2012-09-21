#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include "ld-override.h"

void lookup_function(struct _override *function) {
    char *msg;

    if(function->function_addr != NULL) return;

    function->function_addr = dlsym(RTLD_NEXT, function->function_name);

    if ((msg = dlerror()) != NULL) {
        fprintf(stderr, "dlsym failed for symbol %s: %s\n", function->function_name, msg);
        fflush(stderr);
        exit(1);
    }
}

/*
void wrapper() {}
void skip_real(uintptr_t n) {}
*/

void consistency_check(struct _save_state *state) {}
