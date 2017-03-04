#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vulnerable() {
  char buffer[64];
  memset(buffer, 0, sizeof buffer);
  read(0, buffer, 64);
  printf(buffer);
}

int main() {
  vulnerable();
  return 0;
}
