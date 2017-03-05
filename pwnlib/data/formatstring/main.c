#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int target = 0;

void vulnerable() {
  char buffer[512];
  memset(buffer, 0, sizeof buffer);
  read(0, buffer, sizeof buffer);
  printf(buffer);
}

int main() {
  vulnerable();
  printf("%#x\n", target);
  write(0, &target, sizeof(target));
  return 0;
}
