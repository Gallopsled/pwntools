#include "ld-override.h"
#include <stdlib.h>


void puts(char *);

void printf_wrapper(char *s) {
    puts(s);
    skip_real(4242);
}

WRAP(printf);
