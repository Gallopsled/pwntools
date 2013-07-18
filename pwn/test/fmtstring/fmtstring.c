#include <stdio.h>
#include <string.h>

int main(char *argc, char *argv[]) {
  char buf[1024];
  strncpy(buf, argv[1], sizeof(buf));
  printf("Your input lol:\n");
  printf(buf);
  printf("\n");

  return 0;
}
