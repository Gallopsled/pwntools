#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int run(char * unpacker) {
	void (*shellcode)(void);
        shellcode = unpacker;
        shellcode();
        printf("%s",(char *)shellcode);
    }

	/* should not be reached */
	return EXIT_FAILURE;
}
