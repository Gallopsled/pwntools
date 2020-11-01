#include <stdio.h>
#include <unistd.h>

int main() {
  while (1) {
    char str[256];
    int n = read(STDIN_FILENO, str, sizeof(str) - 1);
    str[n] = '\0';
    printf(str);
    printf("\n=try again=\n");
    fflush(stdout);
  }
  return 0;
}
