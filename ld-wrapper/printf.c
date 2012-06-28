#include "ld-override.h"
#include <stdlib.h>


void puts(char *);

void printf_wrapper(char *s) {
    char *i = s;
    while (*i != '\0') {
        if (*i != '%') {
            i++;
            continue;
        }

        else {
            puts("LOL");
        }
    }
}

WRAP(printf);
