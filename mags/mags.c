#include<stdlib.h>
#include<stdio.h>
#include<sys/stat.h>
#include<sys/types.h>

#include<magic.h>



static magic_t magic_cookie;


void init()
{
  magic_cookie = magic_open(MAGIC_CONTINUE |
                            MAGIC_NO_CHECK_FORTRAN |
                            MAGIC_NO_CHECK_TROFF |
                            MAGIC_NO_CHECK_TOKENS);
  if (magic_cookie == NULL) {
    printf("unable to initialize magic library\n");
    exit(1);
  }
  if (magic_load(magic_cookie, NULL) != 0) {
    printf("cannot load magic database - %s\n", magic_error(magic_cookie));
    magic_close(magic_cookie);
    exit(1);
  }
}


static char* data = "data\0";
char* magic(int idx, const char* buffer, size_t len) {
  char* res;
  if ((res = magic_buffer(magic_cookie, buffer, len)) == NULL) {
  } else {
    if(strcmp(data, res)) {
      printf("%d: %s\n", idx, res);
    }
  }
  return res;
}


int main(int argn, char **argv) {

  // magic init
  init();

  // read file
  if (argn < 2) {
    printf("usage: %s file\n", argv[0]);
    exit(1);
  }

  char* path = argv[1];

  // get file length
  struct stat fileStat;
  if(stat(path, &fileStat) < 0)
    return 1;

  size_t len = fileStat.st_size;

  // read file
  FILE* fd = fopen(path, "r");
  char* buf = malloc(len);
  fread(buf, len, 1, fd);

  size_t i = 0;
  for(i = 0; i < len-1; i++) {
    magic(i, &buf[i], len-i);
  }

  return 0;

}
