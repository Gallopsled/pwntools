%define NOSYS 0
%define SYS_EXIT 1
%define FORK 2
%define READ 3
%define WRITE 4
%define OPEN 5
; XXX should be         { int open(const char *path, int flags, ...); }
; but we're not ready for `const' or varargs.
; XXX man page says `mode_t mode'.
%define CLOSE 6
%define WAIT4 7
%define CREAT 8
%define LINK 9
%define UNLINK 0
11      AUE_NULL        OBSOL   execv
%define CHDIR 2
%define FCHDIR 3
%define MKNOD 4
%define CHMOD 5
%define CHOWN 6
%define OBREAK 7
%define GETFSSTAT 8
%define LSEEK 9
%define GETPID 0
%define MOUNT 1
; XXX `path' should have type `const char *' but we're not ready for that.
%define UNMOUNT 2
%define SETUID 3
%define GETUID 4
%define GETEUID 5
%define PTRACE 6
%define RECVMSG 7
%define SENDMSG 8
%define RECVFROM 9
%define ACCEPT 0
%define GETPEERNAME 1
%define GETSOCKNAME 2
%define ACCESS 3
%define CHFLAGS 4
%define FCHFLAGS 5
%define SYNC 6
%define KILL 7
%define STAT 8
%define GETPPID 9
%define LSTAT 0
%define DUP 1
%define PIPE 2
%define GETEGID 3
%define PROFIL 4
%define KTRACE 5
%define SIGACTION 6
%define GETGID 7
%define SIGPROCMASK 8
; XXX note nonstandard (bogus) calling convention - the libc stub passes
; us the mask, not a pointer to it, and we return the old mask as the
; (int) return value.
%define GETLOGIN 9
%define SETLOGIN 0
%define ACCT 1
%define SIGPENDING 2
%define SIGALTSTACK 3
%define IOCTL 4
%define REBOOT 5
%define REVOKE 6
%define SYMLINK 7
%define READLINK 8
%define EXECVE 9
%define UMASK 0
%define CHROOT 1
%define FSTAT 2
%define GETKERNINFO 3
%define GETPAGESIZE 4
%define MSYNC 5
%define VFORK 6
67      AUE_NULL        OBSOL   vread
68      AUE_NULL        OBSOL   vwrite
%define SBRK 9
%define SSTK 0
%define MMAP 1
%define OVADVISE 2
%define MUNMAP 3
%define MPROTECT 4
%define MADVISE 5
76      AUE_NULL        OBSOL   vhangup
77      AUE_NULL        OBSOL   vlimit
%define MINCORE 8
%define GETGROUPS 9
%define SETGROUPS 0
%define GETPGRP 1
%define SETPGID 2
%define SETITIMER 3
%define WAIT 4
%define SWAPON 5
%define GETITIMER 6
%define GETHOSTNAME 7
%define SETHOSTNAME 8
%define GETDTABLESIZE 9
%define DUP2 0
91      AUE_NULL        UNIMPL  getdopt
%define FCNTL 2
; XXX should be { int fcntl(int fd, int cmd, ...); }
; but we're not ready for varargs.
%define SELECT 3
94      AUE_NULL        UNIMPL  setdopt
%define FSYNC 5
%define SETPRIORITY 6
%define SOCKET 7
%define CONNECT 8
%define ACCEPT 9
%define GETPRIORITY 0
%define SEND 1
%define RECV 2
%define SIGRETURN 3
%define BIND 4
%define SETSOCKOPT 5
%define LISTEN 6
107     AUE_NULL        OBSOL   vtimes
%define SIGVEC 8
%define SIGBLOCK 9
%define SIGSETMASK 0
%define SIGSUSPEND 1
; XXX note nonstandard (bogus) calling convention - the libc stub passes
; us the mask, not a pointer to it.
%define SIGSTACK 2
%define RECVMSG 3
%define SENDMSG 4
115     AUE_NULL        OBSOL   vtrace
%define GETTIMEOFDAY 6
%define GETRUSAGE 7
%define GETSOCKOPT 8
119     AUE_NULL        UNIMPL  resuba (BSD/OS 2.x)
%define READV 0
%define WRITEV 1
%define SETTIMEOFDAY 2
%define FCHOWN 3
%define FCHMOD 4
%define RECVFROM 5
%define SETREUID 6
%define SETREGID 7
%define RENAME 8
%define TRUNCATE 9
%define FTRUNCATE 0
%define FLOCK 1
%define MKFIFO 2
%define SENDTO 3
%define SHUTDOWN 4
%define SOCKETPAIR 5
%define MKDIR 6
%define RMDIR 7
%define UTIMES 8
139     AUE_NULL        OBSOL   4.2 sigreturn
%define ADJTIME 0
%define GETPEERNAME 1
%define GETHOSTID 2
%define SETHOSTID 3
%define GETRLIMIT 4
%define SETRLIMIT 5
%define KILLPG 6
%define SETSID 7
%define QUOTACTL 8
%define QUOTA 9
%define GETSOCKNAME 0

; Syscalls 151-180 inclusive are reserved for vendor-specific
; system calls.  (This includes various calls added for compatibity
; with other Unix variants.)
; Some of these calls are now supported by BSD...
151     AUE_NULL        UNIMPL  sem_lock (BSD/OS 2.x)
152     AUE_NULL        UNIMPL  sem_wakeup (BSD/OS 2.x)
153     AUE_NULL        UNIMPL  asyncdaemon (BSD/OS 2.x)
; 154 is initialised by the NLM code, if present.
%define NLM_SYSCALL 4
; 155 is initialized by the NFS code, if present.
%define NFSSVC 5
%define GETDIRENTRIES 6
%define STATFS 7
%define FSTATFS 8
159     AUE_NULL        UNIMPL  nosys
%define LGETFH 0
%define GETFH 1
%define GETDOMAINNAME 2
%define SETDOMAINNAME 3
%define UNAME 4
%define SYSARCH 5
%define RTPRIO 6
167     AUE_NULL        UNIMPL  nosys
168     AUE_NULL        UNIMPL  nosys
%define SEMSYS 9
; XXX should be { int semsys(int which, ...); }
%define MSGSYS 0
; XXX should be { int msgsys(int which, ...); }
%define SHMSYS 1
; XXX should be { int shmsys(int which, ...); }
172     AUE_NULL        UNIMPL  nosys
%define FREEBSD6_PREAD 3
%define FREEBSD6_PWRITE 4
%define SETFIB 5
%define NTP_ADJTIME 6
177     AUE_NULL        UNIMPL  sfork (BSD/OS 2.x)
178     AUE_NULL        UNIMPL  getdescriptor (BSD/OS 2.x)
179     AUE_NULL        UNIMPL  setdescriptor (BSD/OS 2.x)
180     AUE_NULL        UNIMPL  nosys

; Syscalls 181-199 are used by/reserved for BSD
%define SETGID 1
%define SETEGID 2
%define SETEUID 3
184     AUE_NULL        UNIMPL  lfs_bmapv
185     AUE_NULL        UNIMPL  lfs_markv
186     AUE_NULL        UNIMPL  lfs_segclean
187     AUE_NULL        UNIMPL  lfs_segwait
%define STAT 8
%define FSTAT 9
%define LSTAT 0
%define PATHCONF 1
%define FPATHCONF 2
193     AUE_NULL        UNIMPL  nosys
%define GETRLIMIT 4
%define SETRLIMIT 5
%define GETDIRENTRIES 6
%define FREEBSD6_MMAP 7
%define NOSYS 8
%define FREEBSD6_LSEEK 9
%define FREEBSD6_TRUNCATE 0
%define FREEBSD6_FTRUNCATE 1
%define __SYSCTL 2
%define MLOCK 3
%define MUNLOCK 4
%define UNDELETE 5
%define FUTIMES 6
%define GETPGID 7
208     AUE_NULL        UNIMPL  newreboot (NetBSD)
%define POLL 9

;
; The following are reserved for loadable syscalls
;
210     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
211     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
212     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
213     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
214     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
215     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
216     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
217     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
218     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
219     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int

;
; The following were introduced with NetBSD/4.4Lite-2
%define __SEMCTL 0
%define SEMGET 1
%define SEMOP 2
223     AUE_NULL        UNIMPL  semconfig
%define MSGCTL 4
%define MSGGET 5
%define MSGSND 6
%define MSGRCV 7
%define SHMAT 8
%define SHMCTL 9
%define SHMDT 0
%define SHMGET 1
;
%define CLOCK_GETTIME 2
%define CLOCK_SETTIME 3
%define CLOCK_GETRES 4
%define KTIMER_CREATE 5
%define KTIMER_DELETE 6
%define KTIMER_SETTIME 7
%define KTIMER_GETTIME 8
%define KTIMER_GETOVERRUN 9
%define NANOSLEEP 0
%define FFCLOCK_GETCOUNTER 1
%define FFCLOCK_SETESTIMATE 2
%define FFCLOCK_GETESTIMATE 3
244     AUE_NULL        UNIMPL  nosys
245     AUE_NULL        UNIMPL  nosys
246     AUE_NULL        UNIMPL  nosys
247     AUE_NULL        UNIMPL  nosys
%define NTP_GETTIME 8
249     AUE_NULL        UNIMPL  nosys
; syscall numbers initially used in OpenBSD
%define MINHERIT 0
%define RFORK 1
%define OPENBSD_POLL 2
%define ISSETUGID 3
%define LCHOWN 4
%define AIO_READ 5
%define AIO_WRITE 6
%define LIO_LISTIO 7
258     AUE_NULL        UNIMPL  nosys
259     AUE_NULL        UNIMPL  nosys
260     AUE_NULL        UNIMPL  nosys
261     AUE_NULL        UNIMPL  nosys
262     AUE_NULL        UNIMPL  nosys
263     AUE_NULL        UNIMPL  nosys
264     AUE_NULL        UNIMPL  nosys
265     AUE_NULL        UNIMPL  nosys
266     AUE_NULL        UNIMPL  nosys
267     AUE_NULL        UNIMPL  nosys
268     AUE_NULL        UNIMPL  nosys
269     AUE_NULL        UNIMPL  nosys
270     AUE_NULL        UNIMPL  nosys
271     AUE_NULL        UNIMPL  nosys
%define GETDENTS 2
273     AUE_NULL        UNIMPL  nosys
%define LCHMOD 4
%define LCHOWN 5
%define LUTIMES 6
%define MSYNC 7
%define NSTAT 8
%define NFSTAT 9
%define NLSTAT 0
281     AUE_NULL        UNIMPL  nosys
282     AUE_NULL        UNIMPL  nosys
283     AUE_NULL        UNIMPL  nosys
284     AUE_NULL        UNIMPL  nosys
285     AUE_NULL        UNIMPL  nosys
286     AUE_NULL        UNIMPL  nosys
287     AUE_NULL        UNIMPL  nosys
288     AUE_NULL        UNIMPL  nosys
; 289 and 290 from NetBSD (OpenBSD: 267 and 268)
%define PREADV 9
%define PWRITEV 0
291     AUE_NULL        UNIMPL  nosys
292     AUE_NULL        UNIMPL  nosys
293     AUE_NULL        UNIMPL  nosys
294     AUE_NULL        UNIMPL  nosys
295     AUE_NULL        UNIMPL  nosys
296     AUE_NULL        UNIMPL  nosys
; XXX 297 is 300 in NetBSD 
%define FHSTATFS 7
%define FHOPEN 8
%define FHSTAT 9
; syscall numbers for FreeBSD
%define MODNEXT 0
%define MODSTAT 1
%define MODFNEXT 2
%define MODFIND 3
%define KLDLOAD 4
%define KLDUNLOAD 5
%define KLDFIND 6
%define KLDNEXT 7
%define KLDSTAT 8
%define KLDFIRSTMOD 9
%define GETSID 0
%define SETRESUID 1
%define SETRESGID 2
313     AUE_NULL        OBSOL   signanosleep
%define AIO_RETURN 4
%define AIO_SUSPEND 5
%define AIO_CANCEL 6
%define AIO_ERROR 7
%define OAIO_READ 8
%define OAIO_WRITE 9
%define OLIO_LISTIO 0
%define YIELD 1
322     AUE_NULL        OBSOL   thr_sleep
323     AUE_NULL        OBSOL   thr_wakeup
%define MLOCKALL 4
%define MUNLOCKALL 5
%define __GETCWD 6

%define  7
%define  8

%define  9
%define  0

%define  1
%define  2
%define  3
%define  4
%define UTRACE 5
%define SENDFILE 6
%define KLDSYM 7
%define JAIL 8
%define NNPFS_SYSCALL 9
%define SIGPROCMASK 0
%define SIGSUSPEND 1
%define SIGACTION 2
%define SIGPENDING 3
%define SIGRETURN 4
%define SIGTIMEDWAIT 5
%define SIGWAITINFO 6
%define __ACL_GET_FILE 7
%define __ACL_SET_FILE 8
%define __ACL_GET_FD 9
%define __ACL_SET_FD 0
%define __ACL_DELETE_FILE 1
%define __ACL_DELETE_FD 2
%define __ACL_ACLCHECK_FILE 3
%define __ACL_ACLCHECK_FD 4
%define EXTATTRCTL 5
%define EXTATTR_SET_FILE 6
%define EXTATTR_GET_FILE 7
%define EXTATTR_DELETE_FILE 8
%define AIO_WAITCOMPLETE 9
%define GETRESUID 0
%define GETRESGID 1
%define KQUEUE 2
%define KEVENT 3
364     AUE_NULL        UNIMPL  __cap_get_proc
365     AUE_NULL        UNIMPL  __cap_set_proc
366     AUE_NULL        UNIMPL  __cap_get_fd
367     AUE_NULL        UNIMPL  __cap_get_file
368     AUE_NULL        UNIMPL  __cap_set_fd
369     AUE_NULL        UNIMPL  __cap_set_file
370     AUE_NULL        UNIMPL  nosys
%define EXTATTR_SET_FD 1
%define EXTATTR_GET_FD 2
%define EXTATTR_DELETE_FD 3
%define __SETUGID 4
375     AUE_NULL        UNIMPL  nfsclnt
%define EACCESS 6
%define AFS3_SYSCALL 7
%define NMOUNT 8
379     AUE_NULL        UNIMPL  kse_exit
380     AUE_NULL        UNIMPL  kse_wakeup
381     AUE_NULL        UNIMPL  kse_create
382     AUE_NULL        UNIMPL  kse_thr_interrupt
383     AUE_NULL        UNIMPL  kse_release
%define __MAC_GET_PROC 4
%define __MAC_SET_PROC 5
%define __MAC_GET_FD 6
%define __MAC_GET_FILE 7
%define __MAC_SET_FD 8
%define __MAC_SET_FILE 9
%define KENV 0
%define LCHFLAGS 1
%define UUIDGEN 2
%define SENDFILE 3
%define MAC_SYSCALL 4
%define GETFSSTAT 5
%define STATFS 6
%define FSTATFS 7
%define FHSTATFS 8
399     AUE_NULL        UNIMPL  nosys
%define KSEM_CLOSE 0
%define KSEM_POST 1
%define KSEM_WAIT 2
%define KSEM_TRYWAIT 3
%define KSEM_INIT 4
%define KSEM_OPEN 5
%define KSEM_UNLINK 6
%define KSEM_GETVALUE 7
%define KSEM_DESTROY 8
%define __MAC_GET_PID 9
%define __MAC_GET_LINK 0
%define __MAC_SET_LINK 1
%define EXTATTR_SET_LINK 2
%define EXTATTR_GET_LINK 3
%define EXTATTR_DELETE_LINK 4
%define __MAC_EXECVE 5
%define SIGACTION 6
%define SIGRETURN 7
418     AUE_NULL        UNIMPL  __xstat
419     AUE_NULL        UNIMPL  __xfstat
420     AUE_NULL        UNIMPL  __xlstat
%define GETCONTEXT 1
%define SETCONTEXT 2
%define SWAPCONTEXT 3
%define SWAPOFF 4
%define __ACL_GET_LINK 5
%define __ACL_SET_LINK 6
%define __ACL_DELETE_LINK 7
%define __ACL_ACLCHECK_LINK 8
%define SIGWAIT 9
%define THR_CREATE 0
%define THR_EXIT 1
%define THR_SELF 2
%define THR_KILL 3
%define _UMTX_LOCK 4
%define _UMTX_UNLOCK 5
%define JAIL_ATTACH 6
%define EXTATTR_LIST_FD 7
%define EXTATTR_LIST_FILE 8
%define EXTATTR_LIST_LINK 9
440     AUE_NULL        UNIMPL  kse_switchin
%define KSEM_TIMEDWAIT 1
%define THR_SUSPEND 2
%define THR_WAKE 3
%define KLDUNLOADF 4
%define AUDIT 5
%define AUDITON 6
%define GETAUID 7
%define SETAUID 8
%define GETAUDIT 9
%define SETAUDIT 0
%define GETAUDIT_ADDR 1
%define SETAUDIT_ADDR 2
%define AUDITCTL 3
%define _UMTX_OP 4
%define THR_NEW 5
%define SIGQUEUE 6
%define KMQ_OPEN 7
%define KMQ_SETATTR 8
%define KMQ_TIMEDRECEIVE 9
%define KMQ_TIMEDSEND 0
%define KMQ_NOTIFY 1
%define KMQ_UNLINK 2
%define ABORT2 3
%define THR_SET_NAME 4
%define AIO_FSYNC 5
%define RTPRIO_THREAD 6
467     AUE_NULL        UNIMPL  nosys
468     AUE_NULL        UNIMPL  nosys
469     AUE_NULL        UNIMPL  __getpath_fromfd
470     AUE_NULL        UNIMPL  __getpath_fromaddr
%define SCTP_PEELOFF 1
%define SCTP_GENERIC_SENDMSG 2
%define SCTP_GENERIC_SENDMSG_IOV 3
%define SCTP_GENERIC_RECVMSG 4
%define PREAD 5
%define PWRITE 6
%define MMAP 7
%define LSEEK 8
%define TRUNCATE 9
%define FTRUNCATE 0
%define THR_KILL2 1
%define SHM_OPEN 2
%define SHM_UNLINK 3
%define CPUSET 4
%define CPUSET_SETID 5
%define CPUSET_GETID 6
%define CPUSET_GETAFFINITY 7
%define CPUSET_SETAFFINITY 8
%define FACCESSAT 9
%define FCHMODAT 0
%define FCHOWNAT 1
%define FEXECVE 2
%define FSTATAT 3
%define FUTIMESAT 4
%define LINKAT 5
%define MKDIRAT 6
%define MKFIFOAT 7
%define MKNODAT 8
; XXX: see the comment for open
%define OPENAT 9
%define READLINKAT 0
%define RENAMEAT 1
%define SYMLINKAT 2
%define UNLINKAT 3
%define POSIX_OPENPT 4
; 505 is initialised by the kgssapi code, if present.
%define GSSD_SYSCALL 5
%define JAIL_GET 6
%define JAIL_SET 7
%define JAIL_REMOVE 8
%define CLOSEFROM 9
%define __SEMCTL 0
%define MSGCTL 1
%define SHMCTL 2
%define LPATHCONF 3
%define CAP_NEW 4
%define CAP_GETRIGHTS 5
%define CAP_ENTER 6
%define CAP_GETMODE 7
%define PDFORK 8
%define PDKILL 9
%define PDGETPID 0
521     AUE_PDWAIT      UNIMPL  pdwait4
%define PSELECT 2
%define GETLOGINCLASS 3
%define SETLOGINCLASS 4
%define RCTL_GET_RACCT 5
%define RCTL_GET_RULES 6
%define RCTL_GET_LIMITS 7
%define RCTL_ADD_RULE 8
%define RCTL_REMOVE_RULE 9
%define POSIX_FALLOCATE 0
%define NOSYS 1
%define SYS_EXIT 1
%define FORK 2
%define READ 3
%define WRITE 4
%define OPEN 5
; XXX should be         { int open(const char *path, int flags, ...); }
; but we're not ready for `const' or varargs.
; XXX man page says `mode_t mode'.
%define CLOSE 6
%define WAIT4 7
%define CREAT 8
%define LINK 9
%define UNLINK 0
11      AUE_NULL        OBSOL   execv
%define CHDIR 2
%define FCHDIR 3
%define MKNOD 4
%define CHMOD 5
%define CHOWN 6
%define OBREAK 7
%define GETFSSTAT 8
%define LSEEK 9
%define GETPID 0
%define MOUNT 1
; XXX `path' should have type `const char *' but we're not ready for that.
%define UNMOUNT 2
%define SETUID 3
%define GETUID 4
%define GETEUID 5
%define PTRACE 6
%define RECVMSG 7
%define SENDMSG 8
%define RECVFROM 9
%define ACCEPT 0
%define GETPEERNAME 1
%define GETSOCKNAME 2
%define ACCESS 3
%define CHFLAGS 4
%define FCHFLAGS 5
%define SYNC 6
%define KILL 7
%define STAT 8
%define GETPPID 9
%define LSTAT 0
%define DUP 1
%define PIPE 2
%define GETEGID 3
%define PROFIL 4
%define KTRACE 5
%define SIGACTION 6
%define GETGID 7
%define SIGPROCMASK 8
; XXX note nonstandard (bogus) calling convention - the libc stub passes
; us the mask, not a pointer to it, and we return the old mask as the
; (int) return value.
%define GETLOGIN 9
%define SETLOGIN 0
%define ACCT 1
%define SIGPENDING 2
%define SIGALTSTACK 3
%define IOCTL 4
%define REBOOT 5
%define REVOKE 6
%define SYMLINK 7
%define READLINK 8
%define EXECVE 9
%define UMASK 0
%define CHROOT 1
%define FSTAT 2
%define GETKERNINFO 3
%define GETPAGESIZE 4
%define MSYNC 5
%define VFORK 6
67      AUE_NULL        OBSOL   vread
68      AUE_NULL        OBSOL   vwrite
%define SBRK 9
%define SSTK 0
%define MMAP 1
%define OVADVISE 2
%define MUNMAP 3
%define MPROTECT 4
%define MADVISE 5
76      AUE_NULL        OBSOL   vhangup
77      AUE_NULL        OBSOL   vlimit
%define MINCORE 8
%define GETGROUPS 9
%define SETGROUPS 0
%define GETPGRP 1
%define SETPGID 2
%define SETITIMER 3
%define WAIT 4
%define SWAPON 5
%define GETITIMER 6
%define GETHOSTNAME 7
%define SETHOSTNAME 8
%define GETDTABLESIZE 9
%define DUP2 0
91      AUE_NULL        UNIMPL  getdopt
%define FCNTL 2
; XXX should be { int fcntl(int fd, int cmd, ...); }
; but we're not ready for varargs.
%define SELECT 3
94      AUE_NULL        UNIMPL  setdopt
%define FSYNC 5
%define SETPRIORITY 6
%define SOCKET 7
%define CONNECT 8
%define ACCEPT 9
%define GETPRIORITY 0
%define SEND 1
%define RECV 2
%define SIGRETURN 3
%define BIND 4
%define SETSOCKOPT 5
%define LISTEN 6
107     AUE_NULL        OBSOL   vtimes
%define SIGVEC 8
%define SIGBLOCK 9
%define SIGSETMASK 0
%define SIGSUSPEND 1
; XXX note nonstandard (bogus) calling convention - the libc stub passes
; us the mask, not a pointer to it.
%define SIGSTACK 2
%define RECVMSG 3
%define SENDMSG 4
115     AUE_NULL        OBSOL   vtrace
%define GETTIMEOFDAY 6
%define GETRUSAGE 7
%define GETSOCKOPT 8
119     AUE_NULL        UNIMPL  resuba (BSD/OS 2.x)
%define READV 0
%define WRITEV 1
%define SETTIMEOFDAY 2
%define FCHOWN 3
%define FCHMOD 4
%define RECVFROM 5
%define SETREUID 6
%define SETREGID 7
%define RENAME 8
%define TRUNCATE 9
%define FTRUNCATE 0
%define FLOCK 1
%define MKFIFO 2
%define SENDTO 3
%define SHUTDOWN 4
%define SOCKETPAIR 5
%define MKDIR 6
%define RMDIR 7
%define UTIMES 8
139     AUE_NULL        OBSOL   4.2 sigreturn
%define ADJTIME 0
%define GETPEERNAME 1
%define GETHOSTID 2
%define SETHOSTID 3
%define GETRLIMIT 4
%define SETRLIMIT 5
%define KILLPG 6
%define SETSID 7
%define QUOTACTL 8
%define QUOTA 9
%define GETSOCKNAME 0

; Syscalls 151-180 inclusive are reserved for vendor-specific
; system calls.  (This includes various calls added for compatibity
; with other Unix variants.)
; Some of these calls are now supported by BSD...
151     AUE_NULL        UNIMPL  sem_lock (BSD/OS 2.x)
152     AUE_NULL        UNIMPL  sem_wakeup (BSD/OS 2.x)
153     AUE_NULL        UNIMPL  asyncdaemon (BSD/OS 2.x)
; 154 is initialised by the NLM code, if present.
%define NLM_SYSCALL 4
; 155 is initialized by the NFS code, if present.
%define NFSSVC 5
%define GETDIRENTRIES 6
%define STATFS 7
%define FSTATFS 8
159     AUE_NULL        UNIMPL  nosys
%define LGETFH 0
%define GETFH 1
%define GETDOMAINNAME 2
%define SETDOMAINNAME 3
%define UNAME 4
%define SYSARCH 5
%define RTPRIO 6
167     AUE_NULL        UNIMPL  nosys
168     AUE_NULL        UNIMPL  nosys
%define SEMSYS 9
; XXX should be { int semsys(int which, ...); }
%define MSGSYS 0
; XXX should be { int msgsys(int which, ...); }
%define SHMSYS 1
; XXX should be { int shmsys(int which, ...); }
172     AUE_NULL        UNIMPL  nosys
%define FREEBSD6_PREAD 3
%define FREEBSD6_PWRITE 4
%define SETFIB 5
%define NTP_ADJTIME 6
177     AUE_NULL        UNIMPL  sfork (BSD/OS 2.x)
178     AUE_NULL        UNIMPL  getdescriptor (BSD/OS 2.x)
179     AUE_NULL        UNIMPL  setdescriptor (BSD/OS 2.x)
180     AUE_NULL        UNIMPL  nosys

; Syscalls 181-199 are used by/reserved for BSD
%define SETGID 1
%define SETEGID 2
%define SETEUID 3
184     AUE_NULL        UNIMPL  lfs_bmapv
185     AUE_NULL        UNIMPL  lfs_markv
186     AUE_NULL        UNIMPL  lfs_segclean
187     AUE_NULL        UNIMPL  lfs_segwait
%define STAT 8
%define FSTAT 9
%define LSTAT 0
%define PATHCONF 1
%define FPATHCONF 2
193     AUE_NULL        UNIMPL  nosys
%define GETRLIMIT 4
%define SETRLIMIT 5
%define GETDIRENTRIES 6
%define FREEBSD6_MMAP 7
%define NOSYS 8
%define FREEBSD6_LSEEK 9
%define FREEBSD6_TRUNCATE 0
%define FREEBSD6_FTRUNCATE 1
%define __SYSCTL 2
%define MLOCK 3
%define MUNLOCK 4
%define UNDELETE 5
%define FUTIMES 6
%define GETPGID 7
208     AUE_NULL        UNIMPL  newreboot (NetBSD)
%define POLL 9

;
; The following are reserved for loadable syscalls
;
210     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
211     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
212     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
213     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
214     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
215     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
216     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
217     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
218     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int
219     AUE_NULL        NODEF|NOTSTATIC lkmnosys lkmnosys nosys_args int

;
; The following were introduced with NetBSD/4.4Lite-2
%define __SEMCTL 0
%define SEMGET 1
%define SEMOP 2
223     AUE_NULL        UNIMPL  semconfig
%define MSGCTL 4
%define MSGGET 5
%define MSGSND 6
%define MSGRCV 7
%define SHMAT 8
%define SHMCTL 9
%define SHMDT 0
%define SHMGET 1
;
%define CLOCK_GETTIME 2
%define CLOCK_SETTIME 3
%define CLOCK_GETRES 4
%define KTIMER_CREATE 5
%define KTIMER_DELETE 6
%define KTIMER_SETTIME 7
%define KTIMER_GETTIME 8
%define KTIMER_GETOVERRUN 9
%define NANOSLEEP 0
%define FFCLOCK_GETCOUNTER 1
%define FFCLOCK_SETESTIMATE 2
%define FFCLOCK_GETESTIMATE 3
244     AUE_NULL        UNIMPL  nosys
245     AUE_NULL        UNIMPL  nosys
246     AUE_NULL        UNIMPL  nosys
247     AUE_NULL        UNIMPL  nosys
%define NTP_GETTIME 8
249     AUE_NULL        UNIMPL  nosys
; syscall numbers initially used in OpenBSD
%define MINHERIT 0
%define RFORK 1
%define OPENBSD_POLL 2
%define ISSETUGID 3
%define LCHOWN 4
%define AIO_READ 5
%define AIO_WRITE 6
%define LIO_LISTIO 7
258     AUE_NULL        UNIMPL  nosys
259     AUE_NULL        UNIMPL  nosys
260     AUE_NULL        UNIMPL  nosys
261     AUE_NULL        UNIMPL  nosys
262     AUE_NULL        UNIMPL  nosys
263     AUE_NULL        UNIMPL  nosys
264     AUE_NULL        UNIMPL  nosys
265     AUE_NULL        UNIMPL  nosys
266     AUE_NULL        UNIMPL  nosys
267     AUE_NULL        UNIMPL  nosys
268     AUE_NULL        UNIMPL  nosys
269     AUE_NULL        UNIMPL  nosys
270     AUE_NULL        UNIMPL  nosys
271     AUE_NULL        UNIMPL  nosys
%define GETDENTS 2
273     AUE_NULL        UNIMPL  nosys
%define LCHMOD 4
%define LCHOWN 5
%define LUTIMES 6
%define MSYNC 7
%define NSTAT 8
%define NFSTAT 9
%define NLSTAT 0
281     AUE_NULL        UNIMPL  nosys
282     AUE_NULL        UNIMPL  nosys
283     AUE_NULL        UNIMPL  nosys
284     AUE_NULL        UNIMPL  nosys
285     AUE_NULL        UNIMPL  nosys
286     AUE_NULL        UNIMPL  nosys
287     AUE_NULL        UNIMPL  nosys
288     AUE_NULL        UNIMPL  nosys
; 289 and 290 from NetBSD (OpenBSD: 267 and 268)
%define PREADV 9
%define PWRITEV 0
291     AUE_NULL        UNIMPL  nosys
292     AUE_NULL        UNIMPL  nosys
293     AUE_NULL        UNIMPL  nosys
294     AUE_NULL        UNIMPL  nosys
295     AUE_NULL        UNIMPL  nosys
296     AUE_NULL        UNIMPL  nosys
; XXX 297 is 300 in NetBSD 
%define FHSTATFS 7
%define FHOPEN 8
%define FHSTAT 9
; syscall numbers for FreeBSD
%define MODNEXT 0
%define MODSTAT 1
%define MODFNEXT 2
%define MODFIND 3
%define KLDLOAD 4
%define KLDUNLOAD 5
%define KLDFIND 6
%define KLDNEXT 7
%define KLDSTAT 8
%define KLDFIRSTMOD 9
%define GETSID 0
%define SETRESUID 1
%define SETRESGID 2
313     AUE_NULL        OBSOL   signanosleep
%define AIO_RETURN 4
%define AIO_SUSPEND 5
%define AIO_CANCEL 6
%define AIO_ERROR 7
%define OAIO_READ 8
%define OAIO_WRITE 9
%define OLIO_LISTIO 0
%define YIELD 1
322     AUE_NULL        OBSOL   thr_sleep
323     AUE_NULL        OBSOL   thr_wakeup
%define MLOCKALL 4
%define MUNLOCKALL 5
%define __GETCWD 6

%define  7
%define  8

%define  9
%define  0

%define  1
%define  2
%define  3
%define  4
%define UTRACE 5
%define SENDFILE 6
%define KLDSYM 7
%define JAIL 8
%define NNPFS_SYSCALL 9
%define SIGPROCMASK 0
%define SIGSUSPEND 1
%define SIGACTION 2
%define SIGPENDING 3
%define SIGRETURN 4
%define SIGTIMEDWAIT 5
%define SIGWAITINFO 6
%define __ACL_GET_FILE 7
%define __ACL_SET_FILE 8
%define __ACL_GET_FD 9
%define __ACL_SET_FD 0
%define __ACL_DELETE_FILE 1
%define __ACL_DELETE_FD 2
%define __ACL_ACLCHECK_FILE 3
%define __ACL_ACLCHECK_FD 4
%define EXTATTRCTL 5
%define EXTATTR_SET_FILE 6
%define EXTATTR_GET_FILE 7
%define EXTATTR_DELETE_FILE 8
%define AIO_WAITCOMPLETE 9
%define GETRESUID 0
%define GETRESGID 1
%define KQUEUE 2
%define KEVENT 3
364     AUE_NULL        UNIMPL  __cap_get_proc
365     AUE_NULL        UNIMPL  __cap_set_proc
366     AUE_NULL        UNIMPL  __cap_get_fd
367     AUE_NULL        UNIMPL  __cap_get_file
368     AUE_NULL        UNIMPL  __cap_set_fd
369     AUE_NULL        UNIMPL  __cap_set_file
370     AUE_NULL        UNIMPL  nosys
%define EXTATTR_SET_FD 1
%define EXTATTR_GET_FD 2
%define EXTATTR_DELETE_FD 3
%define __SETUGID 4
375     AUE_NULL        UNIMPL  nfsclnt
%define EACCESS 6
%define AFS3_SYSCALL 7
%define NMOUNT 8
379     AUE_NULL        UNIMPL  kse_exit
380     AUE_NULL        UNIMPL  kse_wakeup
381     AUE_NULL        UNIMPL  kse_create
382     AUE_NULL        UNIMPL  kse_thr_interrupt
383     AUE_NULL        UNIMPL  kse_release
%define __MAC_GET_PROC 4
%define __MAC_SET_PROC 5
%define __MAC_GET_FD 6
%define __MAC_GET_FILE 7
%define __MAC_SET_FD 8
%define __MAC_SET_FILE 9
%define KENV 0
%define LCHFLAGS 1
%define UUIDGEN 2
%define SENDFILE 3
%define MAC_SYSCALL 4
%define GETFSSTAT 5
%define STATFS 6
%define FSTATFS 7
%define FHSTATFS 8
399     AUE_NULL        UNIMPL  nosys
%define KSEM_CLOSE 0
%define KSEM_POST 1
%define KSEM_WAIT 2
%define KSEM_TRYWAIT 3
%define KSEM_INIT 4
%define KSEM_OPEN 5
%define KSEM_UNLINK 6
%define KSEM_GETVALUE 7
%define KSEM_DESTROY 8
%define __MAC_GET_PID 9
%define __MAC_GET_LINK 0
%define __MAC_SET_LINK 1
%define EXTATTR_SET_LINK 2
%define EXTATTR_GET_LINK 3
%define EXTATTR_DELETE_LINK 4
%define __MAC_EXECVE 5
%define SIGACTION 6
%define SIGRETURN 7
418     AUE_NULL        UNIMPL  __xstat
419     AUE_NULL        UNIMPL  __xfstat
420     AUE_NULL        UNIMPL  __xlstat
%define GETCONTEXT 1
%define SETCONTEXT 2
%define SWAPCONTEXT 3
%define SWAPOFF 4
%define __ACL_GET_LINK 5
%define __ACL_SET_LINK 6
%define __ACL_DELETE_LINK 7
%define __ACL_ACLCHECK_LINK 8
%define SIGWAIT 9
%define THR_CREATE 0
%define THR_EXIT 1
%define THR_SELF 2
%define THR_KILL 3
%define _UMTX_LOCK 4
%define _UMTX_UNLOCK 5
%define JAIL_ATTACH 6
%define EXTATTR_LIST_FD 7
%define EXTATTR_LIST_FILE 8
%define EXTATTR_LIST_LINK 9
440     AUE_NULL        UNIMPL  kse_switchin
%define KSEM_TIMEDWAIT 1
%define THR_SUSPEND 2
%define THR_WAKE 3
%define KLDUNLOADF 4
%define AUDIT 5
%define AUDITON 6
%define GETAUID 7
%define SETAUID 8
%define GETAUDIT 9
%define SETAUDIT 0
%define GETAUDIT_ADDR 1
%define SETAUDIT_ADDR 2
%define AUDITCTL 3
%define _UMTX_OP 4
%define THR_NEW 5
%define SIGQUEUE 6
%define KMQ_OPEN 7
%define KMQ_SETATTR 8
%define KMQ_TIMEDRECEIVE 9
%define KMQ_TIMEDSEND 0
%define KMQ_NOTIFY 1
%define KMQ_UNLINK 2
%define ABORT2 3
%define THR_SET_NAME 4
%define AIO_FSYNC 5
%define RTPRIO_THREAD 6
467     AUE_NULL        UNIMPL  nosys
468     AUE_NULL        UNIMPL  nosys
469     AUE_NULL        UNIMPL  __getpath_fromfd
470     AUE_NULL        UNIMPL  __getpath_fromaddr
%define SCTP_PEELOFF 1
%define SCTP_GENERIC_SENDMSG 2
%define SCTP_GENERIC_SENDMSG_IOV 3
%define SCTP_GENERIC_RECVMSG 4
%define PREAD 5
%define PWRITE 6
%define MMAP 7
%define LSEEK 8
%define TRUNCATE 9
%define FTRUNCATE 0
%define THR_KILL2 1
%define SHM_OPEN 2
%define SHM_UNLINK 3
%define CPUSET 4
%define CPUSET_SETID 5
%define CPUSET_GETID 6
%define CPUSET_GETAFFINITY 7
%define CPUSET_SETAFFINITY 8
%define FACCESSAT 9
%define FCHMODAT 0
%define FCHOWNAT 1
%define FEXECVE 2
%define FSTATAT 3
%define FUTIMESAT 4
%define LINKAT 5
%define MKDIRAT 6
%define MKFIFOAT 7
%define MKNODAT 8
; XXX: see the comment for open
%define OPENAT 9
%define READLINKAT 0
%define RENAMEAT 1
%define SYMLINKAT 2
%define UNLINKAT 3
%define POSIX_OPENPT 4
; 505 is initialised by the kgssapi code, if present.
%define GSSD_SYSCALL 5
%define JAIL_GET 6
%define JAIL_SET 7
%define JAIL_REMOVE 8
%define CLOSEFROM 9
%define __SEMCTL 0
%define MSGCTL 1
%define SHMCTL 2
%define LPATHCONF 3
%define CAP_NEW 4
%define CAP_GETRIGHTS 5
%define CAP_ENTER 6
%define CAP_GETMODE 7
%define PDFORK 8
%define PDKILL 9
%define PDGETPID 0
521     AUE_PDWAIT      UNIMPL  pdwait4
%define PSELECT 2
%define GETLOGINCLASS 3
%define SETLOGINCLASS 4
%define RCTL_GET_RACCT 5
%define RCTL_GET_RULES 6
%define RCTL_GET_LIMITS 7
%define RCTL_ADD_RULE 8
%define RCTL_REMOVE_RULE 9
%define POSIX_FALLOCATE 0
%define POSIX_FADVISE 1
