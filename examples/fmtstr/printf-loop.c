#include <stdio.h>

int main() {
  while (1) {
    char str[256];
    fgets(str, sizeof(str), stdin);
    printf(str);
	printf("\n=try again=\n");
	fflush(stdout);
  }
  return 0;
}
