/* Only binary should be available. */
#include <stdio.h>

int main(int argc, char *argv[]) {
    char pw[] = "THISISPA55W0RD!";
    if(argc != 2 || strcmp(argv[1], pw)) {
        printf("fail.\n");
        return -1;
    }
    printf("win!\n");
    return 0;
}
