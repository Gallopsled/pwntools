#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>
#include <unistd.h>

thread_local int x;

void malicious_handler(void *arg) {
    printf("Calling handler with %p\n", arg);
}

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("Assume you have some way to leak information about TLS: %p\n", &x);
    printf("Some more information about function to hijack: %p\n", malicious_handler);
    printf("You can't exploit without glibc: %p\n", puts);

    void *p = malloc(0x500);
    printf("To continue destructor chain, a forged link_map and dtor is needed: %p\n", p);

    printf("Then you have some way to read/write pointer_guard\n");
    size_t *where = NULL;
    printf("Where to read? %%p > ");
    scanf("%p", &where);
    printf("Dereferenced value: %#lx\n", where ? *where : 0);
    
    printf("Now perform arbitrary write ability on hijack exit handlers...\n");
    printf("Write addresses in pairs: %%p=%%lx\n");
    size_t value = 0;
    while (scanf("%p=%lx", &where, &value) == 2) {
        *where = value;
    }

    printf("Let's exit to see what will happen:\n");
    return 0;
}
