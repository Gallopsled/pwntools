
#include "bits/syscall.h.in"

#include "aio.h"
#include "alloca.h"
#include "alltypes.h.in"
#include "ar.h"
#include "arpa/ftp.h"
#include "arpa/inet.h"
#include "arpa/nameser.h"
#include "arpa/nameser_compat.h"
#include "arpa/telnet.h"
#include "assert.h"
#include "byteswap.h"
#include "complex.h"
#include "cpio.h"
#include "crypt.h"
#include "ctype.h"
#include "dirent.h"
#include "dlfcn.h"
#include "elf.h"
#include "endian.h"
#include "err.h"
#include "errno.h"
#include "fcntl.h"
#include "bits/fcntl.h"
#include "features.h"
#include "fenv.h"
#include "float.h"
#include "fmtmsg.h"
#include "fnmatch.h"
#include "ftw.h"
#include "getopt.h"
#include "glob.h"
#include "grp.h"
#include "iconv.h"
#include "ifaddrs.h"
#include "inttypes.h"
#include "iso646.h"
#include "langinfo.h"
#include "lastlog.h"
#include "libgen.h"
#include "libintl.h"
#include "limits.h"
#include "link.h"
#include "locale.h"
#include "malloc.h"
#include "math.h"
#include "memory.h"
#include "mntent.h"
#include "monetary.h"
#include "mqueue.h"
#include "net/ethernet.h"
#include "net/if.h"
#include "net/if_arp.h"
#include "net/route.h"
#include "netdb.h"
#include "netinet/ether.h"
#include "netinet/icmp6.h"
#include "netinet/if_ether.h"
#include "netinet/igmp.h"
#include "netinet/in.h"
#include "netinet/in_systm.h"
#include "netinet/ip.h"
#include "netinet/ip6.h"
#include "netinet/ip_icmp.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "netpacket/packet.h"
#include "nl_types.h"
#include "paths.h"
#include "poll.h"
#include "pthread.h"
// #include "pty.h" // errors for 'TIOCSER_TEMT'.
#include "pwd.h"
#include "regex.h"
#include "resolv.h"
#include "sched.h"
#include "search.h"
#include "semaphore.h"
#include "setjmp.h"
#include "shadow.h"
#include "signal.h"
#include "spawn.h"
#include "stdalign.h"
#include "stdarg.h"
#include "stdbool.h"
#include "stdc-predef.h"
#include "stddef.h"
#include "stdint.h"
#include "stdio.h"
#include "stdio_ext.h"
#include "stdlib.h"
#include "stdnoreturn.h"
#include "string.h"
#include "strings.h"
#include "stropts.h"
#include "sys/acct.h"
#include "sys/auxv.h"
#include "sys/cachectl.h"
#include "sys/dir.h"
#include "sys/epoll.h"
#include "sys/eventfd.h"
#include "sys/fanotify.h"
#include "sys/file.h"
#include "sys/fsuid.h"
#include "sys/inotify.h"
#include "sys/io.h"
#include "sys/ioctl.h"
#include "sys/ipc.h"
#include "sys/klog.h"
#include "sys/mman.h"
#include "sys/mount.h"
#include "sys/msg.h"
#include "sys/mtio.h"
#include "sys/param.h"
#include "sys/personality.h"
#include "sys/poll.h"
#include "sys/prctl.h"
#include "sys/procfs.h"
#include "sys/ptrace.h"
#include "sys/quota.h"
#include "sys/reboot.h"
// #include "sys/reg.h" // missing bits/reg.h
#include "sys/resource.h"
#include "sys/select.h"
#include "sys/sem.h"
#include "sys/sendfile.h"
#include "sys/shm.h"
#include "sys/signalfd.h"
#include "sys/socket.h"
#include "sys/stat.h"
#include "sys/statfs.h"
#include "sys/statvfs.h"
#include "sys/stropts.h"
#include "sys/swap.h"
#include "sys/syscall.h"
#include "sys/sysinfo.h"
#include "sys/syslog.h"
#include "sys/sysmacros.h"
// #include "sys/termios.h" // redefines 'TIOCSER_TEMT'.
#include "sys/time.h"
#include "sys/timeb.h"
#include "sys/timerfd.h"
#include "sys/times.h"
#include "sys/timex.h"
#include "sys/ttydefaults.h"
#include "sys/types.h"
#include "sys/ucontext.h"
#include "sys/uio.h"
#include "sys/un.h"
#include "sys/user.h"
#include "sys/utsname.h"
#include "sys/vfs.h"
#include "sys/wait.h"
#include "sys/xattr.h"
#include "syscall.h"
#include "sysexits.h"
#include "syslog.h"
#include "tar.h"
// #include "termios.h" // includes wrong poll.h
#include "tgmath.h"
#include "threads.h"
#include "time.h"
#include "uchar.h"
#include "ucontext.h"
#include "ulimit.h"
#include "unistd.h"
#include "utime.h"
#include "utmp.h"
#include "utmpx.h"
#include "values.h"
#include "wait.h"
#include "wchar.h"
#include "wctype.h"
#include "wordexp.h"

// MUSL does not provide socketcall constants
#define SYS_socketcall_socket           1
#define SYS_socketcall_bind             2
#define SYS_socketcall_connect          3
#define SYS_socketcall_listen           4
#define SYS_socketcall_accept           5
#define SYS_socketcall_getsockname      6
#define SYS_socketcall_getpeername      7
#define SYS_socketcall_socketpair       8
#define SYS_socketcall_send             9
#define SYS_socketcall_recv             10
#define SYS_socketcall_sendto           11
#define SYS_socketcall_recvfrom         12
#define SYS_socketcall_shutdown         13
#define SYS_socketcall_setsockopt       14
#define SYS_socketcall_getsockopt       15
#define SYS_socketcall_sendmsg          16
#define SYS_socketcall_recvmsg          17
#define SYS_socketcall_accept4          18
