#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ld-override.h"

void srand_wrapper(int seed);

WRAP(srand);

void constructor fix_srand () {
    int fd = open("/dev/urandom",O_RDONLY);
    int seed;
    read(fd, &seed, sizeof(seed));

    lookup_function(&_srand_override);
    ((void (*)()) _srand_override.function_addr) (seed);
}

void srand_wrapper(int seed) {
    skip_real(0);
}
