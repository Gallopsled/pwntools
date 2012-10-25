#include <stdio.h>
#include <sys/time.h>

int main() {
    int i;
    struct timeval t;
    gettimeofday(&t, NULL);
    srand(t.tv_usec);
    for(i = 0; i < 100; i++) {
        if(rand() != 4) {
            printf("fail.\n");
            return -1;
        }
    }
    printf("win!\n");
    return 0;
}
