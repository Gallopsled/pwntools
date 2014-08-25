#define __i386__
#include <i386/syscalls.h>
#include <linuxnet.h>
#include <common.h>

#define SYS_socketcall_socket SYS_SOCKET
#define SYS_socketcall_bind SYS_BIND
#define SYS_socketcall_connect SYS_CONNECT
#define SYS_socketcall_listen SYS_LISTEN
#define SYS_socketcall_accept SYS_ACCEPT
#define SYS_socketcall_getsockname SYS_GETSOCKNAME
#define SYS_socketcall_getpeername SYS_GETPEERNAME
#define SYS_socketcall_socketpair SYS_SOCKETPAIR
#define SYS_socketcall_send SYS_SEND
#define SYS_socketcall_recv SYS_RECV
#define SYS_socketcall_sendto SYS_SENDTO
#define SYS_socketcall_recvfrom SYS_RECVFROM
#define SYS_socketcall_shutdown SYS_SHUTDOWN
#define SYS_socketcall_setsockopt SYS_SETSOCKOPT
#define SYS_socketcall_getsockopt SYS_GETSOCKOPT
#define SYS_socketcall_sendmsg SYS_SENDMSG
#define SYS_socketcall_recvmsg SYS_RECVMSG

