#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int target = 0;

int *target_heap = NULL;

void vulnerable_printf() {
  char buffer[512];
  memset(buffer, 0, sizeof buffer);
  read(0, buffer, sizeof buffer);
  printf(buffer);
}

void vulnerable_sprintf() {
  char buffer[512];
  char dest[512];
  memset(buffer, 0, sizeof buffer);
  read(0, buffer, sizeof buffer);
  sprintf(dest, buffer);
}

void vulnerable_snprintf() {
  char buffer[512];
  char dest[512];
  memset(buffer, 0, sizeof buffer);
  read(0, buffer, sizeof buffer);
  snprintf(dest, 512, buffer);
}


int main() {
  target_heap = malloc(sizeof(int));
  *target_heap = 0;
  write(1, &target_heap, sizeof(target_heap));

  while(1) {
  unsigned int choice = getchar();
  write(1, &choice, sizeof(choice));
  switch (choice) {
  case 0:
    vulnerable_printf();
    break;
  case 1:
    vulnerable_sprintf();
    break;
  case 2:
    vulnerable_snprintf();
    break;
  default:
    break;
  }
  }

  write(1, &target, sizeof(target));
  write(1, target_heap, sizeof(*target_heap));
  return 0;
}
