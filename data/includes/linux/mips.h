#define MAP_32BIT 0x40
#define INADDR_ANY 0
#define INADDR_BROADCAST 0xffffffff
#define INADDR_NONE 0xffffffff
#define INADDR_LOOPBACK 0x7f000001
#define EPERM 1
#define ENOENT 2
#define ESRCH 3
#define EINTR 4
#define EIO 5
#define ENXIO 6
#define E2BIG 7
#define ENOEXEC 8
#define EBADF 9
#define ECHILD 10
#define EAGAIN 11
#define ENOMEM 12
#define EACCES 13
#define EFAULT 14
#define ENOTBLK 15
#define EBUSY 16
#define EEXIST 17
#define EXDEV 18
#define ENODEV 19
#define ENOTDIR 20
#define EISDIR 21
#define EINVAL 22
#define ENFILE 23
#define EMFILE 24
#define ENOTTY 25
#define ETXTBSY 26
#define EFBIG 27
#define ENOSPC 28
#define ESPIPE 29
#define EROFS 30
#define EMLINK 31
#define EPIPE 32
#define EDOM 33
#define ERANGE 34
#define ENOMSG 35
#define EIDRM 36
#define ECHRNG 37
#define EL2NSYNC 38
#define EL3HLT 39
#define EL3RST 40
#define ELNRNG 41
#define EUNATCH 42
#define ENOCSI 43
#define EL2HLT 44
#define EDEADLK 45
#define ENOLCK 46
#define EBADE 50
#define EBADR 51
#define EXFULL 52
#define ENOANO 53
#define EBADRQC 54
#define EBADSLT 55
#define EDEADLOCK 56
#define EBFONT 59
#define ENOSTR 60
#define ENODATA 61
#define ETIME 62
#define ENOSR 63
#define ENONET 64
#define ENOPKG 65
#define EREMOTE 66
#define ENOLINK 67
#define EADV 68
#define ESRMNT 69
#define ECOMM 70
#define EPROTO 71
#define EDOTDOT 73
#define EMULTIHOP 74
#define EBADMSG 77
#define ENAMETOOLONG 78
#define EOVERFLOW 79
#define ENOTUNIQ 80
#define EBADFD 81
#define EREMCHG 82
#define ELIBACC 83
#define ELIBBAD 84
#define ELIBSCN 85
#define ELIBMAX 86
#define ELIBEXEC 87
#define EILSEQ 88
#define ENOSYS 89
#define ELOOP 90
#define ERESTART 91
#define ESTRPIPE 92
#define ENOTEMPTY 93
#define EUSERS 94
#define ENOTSOCK 95
#define EDESTADDRREQ 96
#define EMSGSIZE 97
#define EPROTOTYPE 98
#define ENOPROTOOPT 99
#define EPROTONOSUPPORT 120
#define ESOCKTNOSUPPORT 121
#define EOPNOTSUPP 122
#define ENOTSUP 122
#define EPFNOSUPPORT 123
#define EAFNOSUPPORT 124
#define EADDRINUSE 125
#define EADDRNOTAVAIL 126
#define ENETDOWN 127
#define ENETUNREACH 128
#define ENETRESET 129
#define ECONNABORTED 130
#define ECONNRESET 131
#define ENOBUFS 132
#define EISCONN 133
#define ENOTCONN 134
#define EUCLEAN 135
#define ENOTNAM 137
#define ENAVAIL 138
#define EISNAM 139
#define EREMOTEIO 140
#define EINIT 141
#define EREMDEV 142
#define ESHUTDOWN 143
#define ETOOMANYREFS 144
#define ETIMEDOUT 145
#define ECONNREFUSED 146
#define EHOSTDOWN 147
#define EHOSTUNREACH 148
#define EWOULDBLOCK 11
#define EALREADY 149
#define EINPROGRESS 150
#define ESTALE 151
#define ECANCELED 158
#define ENOMEDIUM 159
#define EMEDIUMTYPE 160
#define ENOKEY 161
#define EKEYEXPIRED 162
#define EKEYREVOKED 163
#define EKEYREJECTED 164
#define EDQUOT 1133
#define __SYS_NERR ((164) + 1)
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __BYTE_ORDER 1234
#define __FLOAT_WORD_ORDER 1234
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define BYTE_ORDER 1234
#define __WORDSIZE 64
#define __FSUID_H 1
#define NSIG 32
#define _NSIG 128
#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGIOT 6
#define SIGFPE 8
#define SIGKILL 9
#define SIGSEGV 11
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGUNUSED 31
#define SIGEMT 7
#define SIGBUS 10
#define SIGSYS 12
#define SIGUSR1 16
#define SIGUSR2 17
#define SIGCHLD 18
#define SIGPWR 19
#define SIGWINCH 20
#define SIGURG 21
#define SIGIO 22
#define SIGSTOP 23
#define SIGTSTP 24
#define SIGCONT 25
#define SIGTTIN 26
#define SIGTTOU 27
#define SIGVTALRM 28
#define SIGPROF 29
#define SIGXCPU 30
#define SIGXFSZ 31
#define SIGCLD 18
#define SIGPOLL 22
#define SIGLOST 19
#define SIGRTMIN 32
#define SIGRTMAX (128-1)
#define SA_NOCLDSTOP 0x00000001
#define SA_SIGINFO 0x00000008
#define SA_NOCLDWAIT 0x00010000
#define SA_RESTORER 0x04000000
#define SA_ONSTACK 0x08000000
#define SA_RESTART 0x10000000
#define SA_INTERRUPT 0x20000000
#define SA_NODEFER 0x40000000
#define SA_RESETHAND 0x80000000
#define SA_NOMASK 0x40000000
#define SA_ONESHOT 0x80000000
#define SS_ONSTACK 1
#define SS_DISABLE 2
#define MINSIGSTKSZ 2048
#define SIGSTKSZ 8192
#define SIG_BLOCK 1
#define SIG_UNBLOCK 2
#define SIG_SETMASK 3
#define SI_MAX_SIZE 128
#define SIGEV_SIGNAL 0
#define SIGEV_NONE 1
#define SIGEV_THREAD 2
#define SIGEV_THREAD_ID 4
#define SIGEV_MAX_SIZE 64
#define _SYS_TIME_H 1
#define ITIMER_REAL 0
#define ITIMER_VIRTUAL 1
#define ITIMER_PROF 2
#define FD_SETSIZE 1024
#define R_OK 4
#define W_OK 2
#define X_OK 1
#define F_OK 0
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define _CS_PATH 1
#define _SC_CLK_TCK 1
#define _SC_ARG_MAX 2
#define _SC_NGROUPS_MAX 3
#define _SC_OPEN_MAX 4
#define _SC_PAGESIZE 5
#define _SC_NPROCESSORS_ONLN 6
#define _SC_NPROCESSORS_CONF 6
#define _SC_PHYS_PAGES 7
#define _PC_PATH_MAX 1
#define _PC_VDISABLE 2
#define L_cuserid 17
#define _POSIX_VERSION 199506
#define F_ULOCK 0
#define F_LOCK 1
#define F_TLOCK 2
#define F_TEST 3
#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000
#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100
#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010
#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001
#define S_IREAD 00400
#define S_IWRITE 00200
#define S_IEXEC 00100
#define F_LINUX_SPECIFIC_BASE 1024
#define O_ACCMODE 0x0003
#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_RDWR 0x0002
#define O_APPEND 0x0008
#define O_SYNC 0x0010
#define O_NONBLOCK 0x0080
#define O_CREAT 0x0100
#define O_TRUNC 0x0200
#define O_EXCL 0x0400
#define O_NOCTTY 0x0800
#define FASYNC 0x1000
#define O_LARGEFILE 0x2000
#define O_DIRECT 0x8000
#define O_DIRECTORY 0x10000
#define O_NOFOLLOW 0x20000
#define O_NOATIME 0x40000
#define O_NDELAY 0x0080
#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_GETLK 14
#define F_SETLK 6
#define F_SETLKW 7
#define F_SETOWN 24
#define F_GETOWN 23
#define F_SETSIG 10
#define F_GETSIG 11
#define FD_CLOEXEC 1
#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2
#define F_EXLCK 4
#define F_SHLCK 8
#define F_INPROGRESS 16
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8
#define LOCK_MAND 32
#define LOCK_READ 64
#define LOCK_WRITE 128
#define LOCK_RW 192
#define O_ASYNC 0x1000
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define PROT_NONE 0x0
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x010
#define MAP_NORESERVE 0x0400
#define MAP_ANONYMOUS 0x0800
#define MAP_GROWSDOWN 0x1000
#define MAP_DENYWRITE 0x2000
#define MAP_EXECUTABLE 0x4000
#define MAP_LOCKED 0x8000
#define MAP_POPULATE 0x10000
#define MS_ASYNC 0x0001
#define MS_INVALIDATE 0x0002
#define MS_SYNC 0x0004
#define MCL_CURRENT 1
#define MCL_FUTURE 2
#define MADV_NORMAL 0x0
#define MADV_RANDOM 0x1
#define MADV_SEQUENTIAL 0x2
#define MADV_WILLNEED 0x3
#define MADV_DONTNEED 0x4
#define MAP_ANON 0x0800
#define MAP_FILE 0
#define SOL_SOCKET 0xffff
#define SO_DEBUG 0x0001
#define SO_REUSEADDR 0x0004
#define SO_TYPE 0x1008
#define SO_ERROR 0x1007
#define SO_DONTROUTE 0x0010
#define SO_BROADCAST 0x0020
#define SO_SNDBUF 0x1001
#define SO_RCVBUF 0x1002
#define SO_KEEPALIVE 0x0008
#define SO_OOBINLINE 0x0100
#define SO_NO_CHECK 11
#define SO_PRIORITY 12
#define SO_LINGER 0x0080
#define SO_BSDCOMPAT 14
#define SO_PASSCRED 17
#define SO_PEERCRED 18
#define SO_RCVLOWAT 0x1004
#define SO_SNDLOWAT 0x1003
#define SO_RCVTIMEO 0x1006
#define SO_SNDTIMEO 0x1005
#define SO_ACCEPTCONN 0x1009
#define SO_SNDBUFFORCE 31
#define SO_RCVBUFFORCE 33
#define SO_STYLE 0x1008
#define SO_SECURITY_AUTHENTICATION 22
#define SO_SECURITY_ENCRYPTION_TRANSPORT 23
#define SO_SECURITY_ENCRYPTION_NETWORK 24
#define SO_BINDTODEVICE 25
#define SO_ATTACH_FILTER 26
#define SO_DETACH_FILTER 27
#define SO_PEERNAME 28
#define SO_TIMESTAMP 29
#define SCM_TIMESTAMP 29
#define SOCK_DGRAM 1
#define SOCK_STREAM 2
#define SOCK_RAW 3
#define SOCK_RDM 4
#define SOCK_SEQPACKET 5
#define SOCK_PACKET 10
#define UIO_FASTIOV 8
#define UIO_MAXIOV 1024
#define SCM_RIGHTS 0x01
#define SCM_CREDENTIALS 0x02
#define SCM_CONNECT 0x03
#define AF_UNSPEC 0
#define AF_UNIX 1
#define AF_LOCAL 1
#define AF_INET 2
#define AF_AX25 3
#define AF_IPX 4
#define AF_APPLETALK 5
#define AF_NETROM 6
#define AF_BRIDGE 7
#define AF_ATMPVC 8
#define AF_X25 9
#define AF_INET6 10
#define AF_ROSE 11
#define AF_DECnet 12
#define AF_NETBEUI 13
#define AF_SECURITY 14
#define AF_KEY 15
#define AF_NETLINK 16
#define AF_ROUTE 16
#define AF_PACKET 17
#define AF_ASH 18
#define AF_ECONET 19
#define AF_ATMSVC 20
#define AF_SNA 22
#define AF_IRDA 23
#define AF_PPPOX 24
#define AF_WANPIPE 25
#define AF_MAX 32
#define PF_UNSPEC 0
#define PF_UNIX 1
#define PF_LOCAL 1
#define PF_INET 2
#define PF_AX25 3
#define PF_IPX 4
#define PF_APPLETALK 5
#define PF_NETROM 6
#define PF_BRIDGE 7
#define PF_ATMPVC 8
#define PF_X25 9
#define PF_INET6 10
#define PF_ROSE 11
#define PF_DECnet 12
#define PF_NETBEUI 13
#define PF_SECURITY 14
#define PF_KEY 15
#define PF_NETLINK 16
#define PF_ROUTE 16
#define PF_PACKET 17
#define PF_ASH 18
#define PF_ECONET 19
#define PF_ATMSVC 20
#define PF_SNA 22
#define PF_IRDA 23
#define PF_PPPOX 24
#define PF_WANPIPE 25
#define PF_MAX 32
#define SOMAXCONN 128
#define MSG_OOB 1
#define MSG_PEEK 2
#define MSG_DONTROUTE 4
#define MSG_TRYHARD 4
#define MSG_CTRUNC 8
#define MSG_PROBE 0x10
#define MSG_TRUNC 0x20
#define MSG_DONTWAIT 0x40
#define MSG_EOR 0x80
#define MSG_WAITALL 0x100
#define MSG_FIN 0x200
#define MSG_EOF 0x200
#define MSG_SYN 0x400
#define MSG_CONFIRM 0x800
#define MSG_RST 0x1000
#define MSG_ERRQUEUE 0x2000
#define MSG_NOSIGNAL 0x4000
#define MSG_MORE 0x8000
#define SOL_IP 0
#define SOL_TCP 6
#define SOL_UDP 17
#define SOL_IPV6 41
#define SOL_ICMPV6 58
#define SOL_RAW 255
#define SOL_IPX 256
#define SOL_AX25 257
#define SOL_ATALK 258
#define SOL_NETROM 259
#define SOL_ROSE 260
#define SOL_DECNET 261
#define SOL_X25 262
#define SOL_PACKET 263
#define SOL_ATM 264
#define SOL_AAL 265
#define SOL_IRDA 266
#define IPX_TYPE 1
#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2
#define NI_NOFQDN 1
#define NI_NUMERICHOST 2
#define NI_NAMEREQD 4
#define NI_NUMERICSERV 8
#define NI_DGRAM 16
#define EAI_FAMILY -1
#define EAI_SOCKTYPE -2
#define EAI_BADFLAGS -3
#define EAI_NONAME -4
#define EAI_SERVICE -5
#define EAI_ADDRFAMILY -6
#define EAI_NODATA -7
#define EAI_MEMORY -8
#define EAI_FAIL -9
#define EAI_AGAIN -10
#define EAI_SYSTEM -11
#define AI_NUMERICHOST 1
#define AI_CANONNAME 2
#define AI_PASSIVE 4
#define SIOCADDRT 0x890B
#define SIOCDELRT 0x890C
#define SIOCRTMSG 0x890D
#define SIOCGIFNAME 0x8910
#define SIOCSIFLINK 0x8911
#define SIOCGIFCONF 0x8912
#define SIOCGIFFLAGS 0x8913
#define SIOCSIFFLAGS 0x8914
#define SIOCGIFADDR 0x8915
#define SIOCSIFADDR 0x8916
#define SIOCGIFDSTADDR 0x8917
#define SIOCSIFDSTADDR 0x8918
#define SIOCGIFBRDADDR 0x8919
#define SIOCSIFBRDADDR 0x891a
#define SIOCGIFNETMASK 0x891b
#define SIOCSIFNETMASK 0x891c
#define SIOCGIFMETRIC 0x891d
#define SIOCSIFMETRIC 0x891e
#define SIOCGIFMEM 0x891f
#define SIOCSIFMEM 0x8920
#define SIOCGIFMTU 0x8921
#define SIOCSIFMTU 0x8922
#define SIOCSIFNAME 0x8923
#define SIOCSIFHWADDR 0x8924
#define SIOCGIFENCAP 0x8925
#define SIOCSIFENCAP 0x8926
#define SIOCGIFHWADDR 0x8927
#define SIOCGIFSLAVE 0x8929
#define SIOCSIFSLAVE 0x8930
#define SIOCADDMULTI 0x8931
#define SIOCDELMULTI 0x8932
#define SIOCGIFINDEX 0x8933
#define SIOGIFINDEX 0x8933
#define SIOCSIFPFLAGS 0x8934
#define SIOCGIFPFLAGS 0x8935
#define SIOCDIFADDR 0x8936
#define SIOCSIFHWBROADCAST 0x8937
#define SIOCGIFCOUNT 0x8938
#define SIOCGIFBR 0x8940
#define SIOCSIFBR 0x8941
#define SIOCGIFTXQLEN 0x8942
#define SIOCSIFTXQLEN 0x8943
#define SIOCGIFDIVERT 0x8944
#define SIOCSIFDIVERT 0x8945
#define SIOCETHTOOL 0x8946
#define SIOCDARP 0x8953
#define SIOCGARP 0x8954
#define SIOCSARP 0x8955
#define SIOCDRARP 0x8960
#define SIOCGRARP 0x8961
#define SIOCSRARP 0x8962
#define SIOCGIFMAP 0x8970
#define SIOCSIFMAP 0x8971
#define SIOCADDDLCI 0x8980
#define SIOCDELDLCI 0x8981
#define SIOCDEVPRIVATE 0x89F0
#define PTRACE_TRACEME 0
#define PTRACE_PEEKTEXT 1
#define PTRACE_PEEKDATA 2
#define PTRACE_PEEKUSR 3
#define PTRACE_PEEKUSER 3
#define PTRACE_POKETEXT 4
#define PTRACE_POKEDATA 5
#define PTRACE_POKEUSR 6
#define PTRACE_POKEUSER 6
#define PTRACE_CONT 7
#define PTRACE_KILL 8
#define PTRACE_SINGLESTEP 9
#define PTRACE_ATTACH 0x10
#define PTRACE_DETACH 0x11
#define PTRACE_SYSCALL 24
#define PTRACE_GETEVENTMSG 0x4201
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_SETSIGINFO 0x4203
#define PTRACE_O_TRACESYSGOOD 0x00000001
#define PTRACE_O_TRACEFORK 0x00000002
#define PTRACE_O_TRACEVFORK 0x00000004
#define PTRACE_O_TRACECLONE 0x00000008
#define PTRACE_O_TRACEEXEC 0x00000010
#define PTRACE_O_TRACEVFORKDONE 0x00000020
#define PTRACE_O_TRACEEXIT 0x00000040
#define PTRACE_O_MASK 0x0000007f
#define PTRACE_EVENT_FORK 1
#define PTRACE_EVENT_VFORK 2
#define PTRACE_EVENT_CLONE 3
#define PTRACE_EVENT_EXEC 4
#define PTRACE_EVENT_VFORK_DONE 5
#define PTRACE_EVENT_EXIT 6
#define PT_TRACE_ME 0
#define PT_READ_I 1
#define PT_READ_D 2
#define PT_READ_U 3
#define PT_WRITE_I 4
#define PT_WRITE_D 5
#define PT_WRITE_U 6
#define PT_CONTINUE 7
#define PT_KILL 8
#define PT_STEP 9
#define PT_ATTACH 0x10
#define PT_DETACH 0x11
#define FPR_BASE 32
#define PC 64
#define CAUSE 65
#define BADVADDR 66
#define MMHI 67
#define MMLO 68
#define FPC_CSR 69
#define FPC_EIR 70
#define __NR_Linux 4000
#define __NR_syscall (4000 +   0)
#define __NR_exit (4000 +   1)
#define __NR_fork (4000 +   2)
#define __NR_read (4000 +   3)
#define __NR_write (4000 +   4)
#define __NR_open (4000 +   5)
#define __NR_close (4000 +   6)
#define __NR_waitpid (4000 +   7)
#define __NR_creat (4000 +   8)
#define __NR_link (4000 +   9)
#define __NR_unlink (4000 +  10)
#define __NR_execve (4000 +  11)
#define __NR_chdir (4000 +  12)
#define __NR_time (4000 +  13)
#define __NR_mknod (4000 +  14)
#define __NR_chmod (4000 +  15)
#define __NR_lchown (4000 +  16)
#define __NR_break (4000 +  17)
#define __NR_unused18 (4000 +  18)
#define __NR_lseek (4000 +  19)
#define __NR_getpid (4000 +  20)
#define __NR_mount (4000 +  21)
#define __NR_umount (4000 +  22)
#define __NR_setuid (4000 +  23)
#define __NR_getuid (4000 +  24)
#define __NR_stime (4000 +  25)
#define __NR_ptrace (4000 +  26)
#define __NR_alarm (4000 +  27)
#define __NR_unused28 (4000 +  28)
#define __NR_pause (4000 +  29)
#define __NR_utime (4000 +  30)
#define __NR_stty (4000 +  31)
#define __NR_gtty (4000 +  32)
#define __NR_access (4000 +  33)
#define __NR_nice (4000 +  34)
#define __NR_ftime (4000 +  35)
#define __NR_sync (4000 +  36)
#define __NR_kill (4000 +  37)
#define __NR_rename (4000 +  38)
#define __NR_mkdir (4000 +  39)
#define __NR_rmdir (4000 +  40)
#define __NR_dup (4000 +  41)
#define __NR_pipe (4000 +  42)
#define __NR_times (4000 +  43)
#define __NR_prof (4000 +  44)
#define __NR_brk (4000 +  45)
#define __NR_setgid (4000 +  46)
#define __NR_getgid (4000 +  47)
#define __NR_signal (4000 +  48)
#define __NR_geteuid (4000 +  49)
#define __NR_getegid (4000 +  50)
#define __NR_acct (4000 +  51)
#define __NR_umount2 (4000 +  52)
#define __NR_lock (4000 +  53)
#define __NR_ioctl (4000 +  54)
#define __NR_fcntl (4000 +  55)
#define __NR_mpx (4000 +  56)
#define __NR_setpgid (4000 +  57)
#define __NR_ulimit (4000 +  58)
#define __NR_unused59 (4000 +  59)
#define __NR_umask (4000 +  60)
#define __NR_chroot (4000 +  61)
#define __NR_ustat (4000 +  62)
#define __NR_dup2 (4000 +  63)
#define __NR_getppid (4000 +  64)
#define __NR_getpgrp (4000 +  65)
#define __NR_setsid (4000 +  66)
#define __NR_sigaction (4000 +  67)
#define __NR_sgetmask (4000 +  68)
#define __NR_ssetmask (4000 +  69)
#define __NR_setreuid (4000 +  70)
#define __NR_setregid (4000 +  71)
#define __NR_sigsuspend (4000 +  72)
#define __NR_sigpending (4000 +  73)
#define __NR_sethostname (4000 +  74)
#define __NR_setrlimit (4000 +  75)
#define __NR_getrlimit (4000 +  76)
#define __NR_getrusage (4000 +  77)
#define __NR_gettimeofday (4000 +  78)
#define __NR_settimeofday (4000 +  79)
#define __NR_getgroups (4000 +  80)
#define __NR_setgroups (4000 +  81)
#define __NR_reserved82 (4000 +  82)
#define __NR_symlink (4000 +  83)
#define __NR_unused84 (4000 +  84)
#define __NR_readlink (4000 +  85)
#define __NR_uselib (4000 +  86)
#define __NR_swapon (4000 +  87)
#define __NR_reboot (4000 +  88)
#define __NR_readdir (4000 +  89)
#define __NR_mmap (4000 +  90)
#define __NR_munmap (4000 +  91)
#define __NR_truncate (4000 +  92)
#define __NR_ftruncate (4000 +  93)
#define __NR_fchmod (4000 +  94)
#define __NR_fchown (4000 +  95)
#define __NR_getpriority (4000 +  96)
#define __NR_setpriority (4000 +  97)
#define __NR_profil (4000 +  98)
#define __NR_statfs (4000 +  99)
#define __NR_fstatfs (4000 + 100)
#define __NR_ioperm (4000 + 101)
#define __NR_socketcall (4000 + 102)
#define __NR_syslog (4000 + 103)
#define __NR_setitimer (4000 + 104)
#define __NR_getitimer (4000 + 105)
#define __NR_stat (4000 + 106)
#define __NR_lstat (4000 + 107)
#define __NR_fstat (4000 + 108)
#define __NR_unused109 (4000 + 109)
#define __NR_iopl (4000 + 110)
#define __NR_vhangup (4000 + 111)
#define __NR_idle (4000 + 112)
#define __NR_vm86 (4000 + 113)
#define __NR_wait4 (4000 + 114)
#define __NR_swapoff (4000 + 115)
#define __NR_sysinfo (4000 + 116)
#define __NR_ipc (4000 + 117)
#define __NR_fsync (4000 + 118)
#define __NR_sigreturn (4000 + 119)
#define __NR_clone (4000 + 120)
#define __NR_setdomainname (4000 + 121)
#define __NR_uname (4000 + 122)
#define __NR_modify_ldt (4000 + 123)
#define __NR_adjtimex (4000 + 124)
#define __NR_mprotect (4000 + 125)
#define __NR_sigprocmask (4000 + 126)
#define __NR_create_module (4000 + 127)
#define __NR_init_module (4000 + 128)
#define __NR_delete_module (4000 + 129)
#define __NR_get_kernel_syms (4000 + 130)
#define __NR_quotactl (4000 + 131)
#define __NR_getpgid (4000 + 132)
#define __NR_fchdir (4000 + 133)
#define __NR_bdflush (4000 + 134)
#define __NR_sysfs (4000 + 135)
#define __NR_personality (4000 + 136)
#define __NR_afs_syscall (4000 + 137)
#define __NR_setfsuid (4000 + 138)
#define __NR_setfsgid (4000 + 139)
#define __NR__llseek (4000 + 140)
#define __NR_getdents (4000 + 141)
#define __NR__newselect (4000 + 142)
#define __NR_flock (4000 + 143)
#define __NR_msync (4000 + 144)
#define __NR_readv (4000 + 145)
#define __NR_writev (4000 + 146)
#define __NR_cacheflush (4000 + 147)
#define __NR_cachectl (4000 + 148)
#define __NR_sysmips (4000 + 149)
#define __NR_unused150 (4000 + 150)
#define __NR_getsid (4000 + 151)
#define __NR_fdatasync (4000 + 152)
#define __NR__sysctl (4000 + 153)
#define __NR_mlock (4000 + 154)
#define __NR_munlock (4000 + 155)
#define __NR_mlockall (4000 + 156)
#define __NR_munlockall (4000 + 157)
#define __NR_sched_setparam (4000 + 158)
#define __NR_sched_getparam (4000 + 159)
#define __NR_sched_setscheduler (4000 + 160)
#define __NR_sched_getscheduler (4000 + 161)
#define __NR_sched_yield (4000 + 162)
#define __NR_sched_get_priority_max (4000 + 163)
#define __NR_sched_get_priority_min (4000 + 164)
#define __NR_sched_rr_get_interval (4000 + 165)
#define __NR_nanosleep (4000 + 166)
#define __NR_mremap (4000 + 167)
#define __NR_accept (4000 + 168)
#define __NR_bind (4000 + 169)
#define __NR_connect (4000 + 170)
#define __NR_getpeername (4000 + 171)
#define __NR_getsockname (4000 + 172)
#define __NR_getsockopt (4000 + 173)
#define __NR_listen (4000 + 174)
#define __NR_recv (4000 + 175)
#define __NR_recvfrom (4000 + 176)
#define __NR_recvmsg (4000 + 177)
#define __NR_send (4000 + 178)
#define __NR_sendmsg (4000 + 179)
#define __NR_sendto (4000 + 180)
#define __NR_setsockopt (4000 + 181)
#define __NR_shutdown (4000 + 182)
#define __NR_socket (4000 + 183)
#define __NR_socketpair (4000 + 184)
#define __NR_setresuid (4000 + 185)
#define __NR_getresuid (4000 + 186)
#define __NR_query_module (4000 + 187)
#define __NR_poll (4000 + 188)
#define __NR_nfsservctl (4000 + 189)
#define __NR_setresgid (4000 + 190)
#define __NR_getresgid (4000 + 191)
#define __NR_prctl (4000 + 192)
#define __NR_rt_sigreturn (4000 + 193)
#define __NR_rt_sigaction (4000 + 194)
#define __NR_rt_sigprocmask (4000 + 195)
#define __NR_rt_sigpending (4000 + 196)
#define __NR_rt_sigtimedwait (4000 + 197)
#define __NR_rt_sigqueueinfo (4000 + 198)
#define __NR_rt_sigsuspend (4000 + 199)
#define __NR_pread (4000 + 200)
#define __NR_pwrite (4000 + 201)
#define __NR_chown (4000 + 202)
#define __NR_getcwd (4000 + 203)
#define __NR_capget (4000 + 204)
#define __NR_capset (4000 + 205)
#define __NR_sigaltstack (4000 + 206)
#define __NR_sendfile (4000 + 207)
#define __NR_getpmsg (4000 + 208)
#define __NR_putpmsg (4000 + 209)
#define __NR_mmap2 (4000 + 210)
#define __NR_truncate64 (4000 + 211)
#define __NR_ftruncate64 (4000 + 212)
#define __NR_stat64 (4000 + 213)
#define __NR_lstat64 (4000 + 214)
#define __NR_fstat64 (4000 + 215)
#define __NR_pivot_root (4000 + 216)
#define __NR_mincore (4000 + 217)
#define __NR_madvise (4000 + 218)
#define __NR_getdents64 (4000 + 219)
#define __NR_fcntl64 (4000 + 220)
#define __NR_reserved221 (4000 + 221)
#define __NR_gettid (4000 + 222)
#define __NR_readahead (4000 + 223)
#define __NR_setxattr (4000 + 224)
#define __NR_lsetxattr (4000 + 225)
#define __NR_fsetxattr (4000 + 226)
#define __NR_getxattr (4000 + 227)
#define __NR_lgetxattr (4000 + 228)
#define __NR_fgetxattr (4000 + 229)
#define __NR_listxattr (4000 + 230)
#define __NR_llistxattr (4000 + 231)
#define __NR_flistxattr (4000 + 232)
#define __NR_removexattr (4000 + 233)
#define __NR_lremovexattr (4000 + 234)
#define __NR_fremovexattr (4000 + 235)
#define __NR_tkill (4000 + 236)
#define __NR_sendfile64 (4000 + 237)
#define __NR_futex (4000 + 238)
#define __NR_sched_setaffinity (4000 + 239)
#define __NR_sched_getaffinity (4000 + 240)
#define __NR_io_setup (4000 + 241)
#define __NR_io_destroy (4000 + 242)
#define __NR_io_getevents (4000 + 243)
#define __NR_io_submit (4000 + 244)
#define __NR_io_cancel (4000 + 245)
#define __NR_exit_group (4000 + 246)
#define __NR_lookup_dcookie (4000 + 247)
#define __NR_epoll_create (4000 + 248)
#define __NR_epoll_ctl (4000 + 249)
#define __NR_epoll_wait (4000 + 250)
#define __NR_remap_file_pages (4000 + 251)
#define __NR_set_tid_address (4000 + 252)
#define __NR_restart_syscall (4000 + 253)
#define __NR_fadvise64 (4000 + 254)
#define __NR_statfs64 (4000 + 255)
#define __NR_fstatfs64 (4000 + 256)
#define __NR_timer_create (4000 + 257)
#define __NR_timer_settime (4000 + 258)
#define __NR_timer_gettime (4000 + 259)
#define __NR_timer_getoverrun (4000 + 260)
#define __NR_timer_delete (4000 + 261)
#define __NR_clock_settime (4000 + 262)
#define __NR_clock_gettime (4000 + 263)
#define __NR_clock_getres (4000 + 264)
#define __NR_clock_nanosleep (4000 + 265)
#define __NR_tgkill (4000 + 266)
#define __NR_utimes (4000 + 267)
#define __NR_mbind (4000 + 268)
#define __NR_get_mempolicy (4000 + 269)
#define __NR_set_mempolicy (4000 + 270)
#define __NR_mq_open (4000 + 271)
#define __NR_mq_unlink (4000 + 272)
#define __NR_mq_timedsend (4000 + 273)
#define __NR_mq_timedreceive (4000 + 274)
#define __NR_mq_notify (4000 + 275)
#define __NR_mq_getsetattr (4000 + 276)
#define __NR_vserver (4000 + 277)
#define __NR_waitid (4000 + 278)
#define __NR_add_key (4000 + 280)
#define __NR_request_key (4000 + 281)
#define __NR_keyctl (4000 + 282)
#define __NR_set_thread_area (4000 + 283)
#define __NR_inotify_init (4000 + 284)
#define __NR_inotify_add_watch (4000 + 285)
#define __NR_inotify_rm_watch (4000 + 286)
#define __NR_migrate_pages (4000 + 287)
#define __NR_openat (4000 + 288)
#define __NR_mkdirat (4000 + 289)
#define __NR_mknodat (4000 + 290)
#define __NR_fchownat (4000 + 291)
#define __NR_futimesat (4000 + 292)
#define __NR_fstatat (4000 + 293)
#define __NR_unlinkat (4000 + 294)
#define __NR_renameat (4000 + 295)
#define __NR_linkat (4000 + 296)
#define __NR_symlinkat (4000 + 297)
#define __NR_readlinkat (4000 + 298)
#define __NR_fchmodat (4000 + 299)
#define __NR_faccessat (4000 + 300)
#define __NR_pselect6 (4000 + 301)
#define __NR_ppoll (4000 + 302)
#define __NR_unshare (4000 + 303)
#define __NR_splice (4000 + 304)
#define __NR_sync_file_range (4000 + 305)
#define __NR_tee (4000 + 306)
#define __NR_vmsplice (4000 + 307)
#define __NR_move_pages (4000 + 308)
#define __NR_set_robust_list (4000 + 272)
#define __NR_get_robust_list (4000 + 273)
#define __NR_kexec_load (4000 + 274)
#define __NR_getcpu (4000 + 275)
#define __NR_epoll_pwait (4000 + 276)
#define __NR_ioprio_set (4000 + 277)
#define __NR_ioprio_get (4000 + 278)
#define __NR_utimensat (4000 + 279)
#define __NR_signalfd (4000 + 280)
#define __NR_timerfd (4000 + 281)
#define __NR_eventfd (4000 + 282)
#define __NR_fallocate (4000 + 283)
#define __NR_timerfd_create (4000 + 284)
#define __NR_timerfd_gettime (4000 + 285)
#define __NR_timerfd_settime (4000 + 286)
