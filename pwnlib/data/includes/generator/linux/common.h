#define __ASSEMBLER__
#define MAP_32BIT       0x40 // Only give out 32-bit addresses.
#define INADDR_ANY 0
#define INADDR_BROADCAST 0xffffffff
#define INADDR_NONE 0xffffffff
#define INADDR_LOOPBACK 0x7f000001

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <syscall_map.h>
