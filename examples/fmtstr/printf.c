#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#define MEMORY_ADDRESS ((void*)0x11110000)
#define MEMORY_SIZE 1024
#define TARGET ((int *) 0x11110100)
int main(int argc, char const *argv[])
{
       char buff[1024];
       void *ptr = NULL;
       int *my_var = TARGET;
       ptr = mmap(MEMORY_ADDRESS, MEMORY_SIZE, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
       if(ptr != MEMORY_ADDRESS)
       {
               perror("mmap");
               return EXIT_FAILURE;
       }
       *my_var = 0x41414141;
       write(1, &my_var, sizeof(int *));
       scanf("%s", buff);
       dprintf(2, buff);
       write(1, "DONE", 4);
       write(1, my_var, sizeof(int));
       return 0;
}
