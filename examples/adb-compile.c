#include <stdio.h>

static char buf[4096];

int main()
{
  FILE *fp = fopen("/proc/self/maps", "r");
  int n = fread(buf, 1, sizeof(buf), fp);
  fwrite(buf, 1, n, stdout);
  return 0;
}
