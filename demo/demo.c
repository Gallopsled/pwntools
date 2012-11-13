#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char *stack_space[0x1000];
  int fd;
  struct stat sbuf;
  void (*shellcode)(void);
  int i, z, c, bufsize, numb;
  unsigned char *p;
  if (argc != 2) {
    fprintf(stderr, "Usage: %s (<filename>|-)\n", argv[0]);
    return EXIT_FAILURE;
  }

  if (strcmp(argv[1], "-") == 0) {
    bufsize = 4096;
    p = malloc(bufsize);
    z = 0;
    numb = 0;
    while ((c = getchar()) != EOF) {
      if (numb == bufsize) {
        bufsize += 4096;
        p = realloc(p, bufsize);
      }
      p[numb++] = c;
      if (c == '\0') z++;
    }

    if ((shellcode = mmap(NULL, numb, PROT_READ | PROT_EXEC | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
      perror("mmap() failed");
      return EXIT_FAILURE;
    }
    memcpy(shellcode, p, numb);
    free(p);
  } else {
    if ((fd = open(argv[1], O_RDONLY)) < 0) {
      perror("open() failed");
      return EXIT_FAILURE;
    }
    if (fstat(fd, &sbuf)) {
      perror("fstat() failed");
      return EXIT_FAILURE;
    }
    if ((shellcode = mmap(NULL, sbuf.st_size, PROT_READ | PROT_EXEC | PROT_WRITE,
                          MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
      perror("mmap() failed");
      return EXIT_FAILURE;
    }

    close(fd);
    for (i = 0, z = 0, p = (void *)shellcode; i < sbuf.st_size; i++) {
      if (p[i] == '\0') z++;
    }
    numb = sbuf.st_size;
  }

  printf("Read %d bytes of shell code. Here goes.\n", numb);
  if (z > 0) printf("Shellcode contains %d zero bytes.\n", z);
  printf("~~~ Running shellcode ~~~\n");

  shellcode();

  /* should not be reached */
  return EXIT_FAILURE;
}
