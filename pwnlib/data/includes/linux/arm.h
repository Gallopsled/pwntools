#define __ARM_EABI__ 1
#define __KERNEL__ 1
#define _ARM_SYSCALL_H 1
#define __NR_OABI_SYSCALL_BASE 0x900000
#define __NR_SYSCALL_BASE 0
#define __NR_restart_syscall (0+  0)
#define __NR_exit (0+  1)
#define __NR_fork (0+  2)
#define __NR_read (0+  3)
#define __NR_write (0+  4)
#define __NR_open (0+  5)
#define __NR_close (0+  6)
#define __NR_creat (0+  8)
#define __NR_link (0+  9)
#define __NR_unlink (0+ 10)
#define __NR_execve (0+ 11)
#define __NR_chdir (0+ 12)
#define __NR_time (0+ 13)
#define __NR_mknod (0+ 14)
#define __NR_chmod (0+ 15)
#define __NR_lchown (0+ 16)
#define __NR_lseek (0+ 19)
#define __NR_getpid (0+ 20)
#define __NR_mount (0+ 21)
#define __NR_umount (0+ 22)
#define __NR_setuid (0+ 23)
#define __NR_getuid (0+ 24)
#define __NR_stime (0+ 25)
#define __NR_ptrace (0+ 26)
#define __NR_alarm (0+ 27)
#define __NR_pause (0+ 29)
#define __NR_utime (0+ 30)
#define __NR_access (0+ 33)
#define __NR_nice (0+ 34)
#define __NR_sync (0+ 36)
#define __NR_kill (0+ 37)
#define __NR_rename (0+ 38)
#define __NR_mkdir (0+ 39)
#define __NR_rmdir (0+ 40)
#define __NR_dup (0+ 41)
#define __NR_pipe (0+ 42)
#define __NR_times (0+ 43)
#define __NR_brk (0+ 45)
#define __NR_setgid (0+ 46)
#define __NR_getgid (0+ 47)
#define __NR_geteuid (0+ 49)
#define __NR_getegid (0+ 50)
#define __NR_acct (0+ 51)
#define __NR_umount2 (0+ 52)
#define __NR_ioctl (0+ 54)
#define __NR_fcntl (0+ 55)
#define __NR_setpgid (0+ 57)
#define __NR_umask (0+ 60)
#define __NR_chroot (0+ 61)
#define __NR_ustat (0+ 62)
#define __NR_dup2 (0+ 63)
#define __NR_getppid (0+ 64)
#define __NR_getpgrp (0+ 65)
#define __NR_setsid (0+ 66)
#define __NR_sigaction (0+ 67)
#define __NR_setreuid (0+ 70)
#define __NR_setregid (0+ 71)
#define __NR_sigsuspend (0+ 72)
#define __NR_sigpending (0+ 73)
#define __NR_sethostname (0+ 74)
#define __NR_setrlimit (0+ 75)
#define __NR_getrlimit (0+ 76)
#define __NR_getrusage (0+ 77)
#define __NR_gettimeofday (0+ 78)
#define __NR_settimeofday (0+ 79)
#define __NR_getgroups (0+ 80)
#define __NR_setgroups (0+ 81)
#define __NR_select (0+ 82)
#define __NR_symlink (0+ 83)
#define __NR_readlink (0+ 85)
#define __NR_uselib (0+ 86)
#define __NR_swapon (0+ 87)
#define __NR_reboot (0+ 88)
#define __NR_readdir (0+ 89)
#define __NR_mmap (0+ 90)
#define __NR_munmap (0+ 91)
#define __NR_truncate (0+ 92)
#define __NR_ftruncate (0+ 93)
#define __NR_fchmod (0+ 94)
#define __NR_fchown (0+ 95)
#define __NR_getpriority (0+ 96)
#define __NR_setpriority (0+ 97)
#define __NR_statfs (0+ 99)
#define __NR_fstatfs (0+100)
#define __NR_socketcall (0+102)
#define __NR_syslog (0+103)
#define __NR_setitimer (0+104)
#define __NR_getitimer (0+105)
#define __NR_stat (0+106)
#define __NR_lstat (0+107)
#define __NR_fstat (0+108)
#define __NR_vhangup (0+111)
#define __NR_syscall (0+113)
#define __NR_wait4 (0+114)
#define __NR_swapoff (0+115)
#define __NR_sysinfo (0+116)
#define __NR_ipc (0+117)
#define __NR_fsync (0+118)
#define __NR_sigreturn (0+119)
#define __NR_clone (0+120)
#define __NR_setdomainname (0+121)
#define __NR_uname (0+122)
#define __NR_adjtimex (0+124)
#define __NR_mprotect (0+125)
#define __NR_sigprocmask (0+126)
#define __NR_init_module (0+128)
#define __NR_delete_module (0+129)
#define __NR_quotactl (0+131)
#define __NR_getpgid (0+132)
#define __NR_fchdir (0+133)
#define __NR_bdflush (0+134)
#define __NR_sysfs (0+135)
#define __NR_personality (0+136)
#define __NR_setfsuid (0+138)
#define __NR_setfsgid (0+139)
#define __NR__llseek (0+140)
#define __NR_getdents (0+141)
#define __NR__newselect (0+142)
#define __NR_flock (0+143)
#define __NR_msync (0+144)
#define __NR_readv (0+145)
#define __NR_writev (0+146)
#define __NR_getsid (0+147)
#define __NR_fdatasync (0+148)
#define __NR__sysctl (0+149)
#define __NR_mlock (0+150)
#define __NR_munlock (0+151)
#define __NR_mlockall (0+152)
#define __NR_munlockall (0+153)
#define __NR_sched_setparam (0+154)
#define __NR_sched_getparam (0+155)
#define __NR_sched_setscheduler (0+156)
#define __NR_sched_getscheduler (0+157)
#define __NR_sched_yield (0+158)
#define __NR_sched_get_priority_max (0+159)
#define __NR_sched_get_priority_min (0+160)
#define __NR_sched_rr_get_interval (0+161)
#define __NR_nanosleep (0+162)
#define __NR_mremap (0+163)
#define __NR_setresuid (0+164)
#define __NR_getresuid (0+165)
#define __NR_poll (0+168)
#define __NR_nfsservctl (0+169)
#define __NR_setresgid (0+170)
#define __NR_getresgid (0+171)
#define __NR_prctl (0+172)
#define __NR_rt_sigreturn (0+173)
#define __NR_rt_sigaction (0+174)
#define __NR_rt_sigprocmask (0+175)
#define __NR_rt_sigpending (0+176)
#define __NR_rt_sigtimedwait (0+177)
#define __NR_rt_sigqueueinfo (0+178)
#define __NR_rt_sigsuspend (0+179)
#define __NR_pread64 (0+180)
#define __NR_pwrite64 (0+181)
#define __NR_chown (0+182)
#define __NR_getcwd (0+183)
#define __NR_capget (0+184)
#define __NR_capset (0+185)
#define __NR_sigaltstack (0+186)
#define __NR_sendfile (0+187)
#define __NR_vfork (0+190)
#define __NR_ugetrlimit (0+191)
#define __NR_mmap2 (0+192)
#define __NR_truncate64 (0+193)
#define __NR_ftruncate64 (0+194)
#define __NR_stat64 (0+195)
#define __NR_lstat64 (0+196)
#define __NR_fstat64 (0+197)
#define __NR_lchown32 (0+198)
#define __NR_getuid32 (0+199)
#define __NR_getgid32 (0+200)
#define __NR_geteuid32 (0+201)
#define __NR_getegid32 (0+202)
#define __NR_setreuid32 (0+203)
#define __NR_setregid32 (0+204)
#define __NR_getgroups32 (0+205)
#define __NR_setgroups32 (0+206)
#define __NR_fchown32 (0+207)
#define __NR_setresuid32 (0+208)
#define __NR_getresuid32 (0+209)
#define __NR_setresgid32 (0+210)
#define __NR_getresgid32 (0+211)
#define __NR_chown32 (0+212)
#define __NR_setuid32 (0+213)
#define __NR_setgid32 (0+214)
#define __NR_setfsuid32 (0+215)
#define __NR_setfsgid32 (0+216)
#define __NR_getdents64 (0+217)
#define __NR_pivot_root (0+218)
#define __NR_mincore (0+219)
#define __NR_madvise (0+220)
#define __NR_fcntl64 (0+221)
#define __NR_gettid (0+224)
#define __NR_readahead (0+225)
#define __NR_setxattr (0+226)
#define __NR_lsetxattr (0+227)
#define __NR_fsetxattr (0+228)
#define __NR_getxattr (0+229)
#define __NR_lgetxattr (0+230)
#define __NR_fgetxattr (0+231)
#define __NR_listxattr (0+232)
#define __NR_llistxattr (0+233)
#define __NR_flistxattr (0+234)
#define __NR_removexattr (0+235)
#define __NR_lremovexattr (0+236)
#define __NR_fremovexattr (0+237)
#define __NR_tkill (0+238)
#define __NR_sendfile64 (0+239)
#define __NR_futex (0+240)
#define __NR_sched_setaffinity (0+241)
#define __NR_sched_getaffinity (0+242)
#define __NR_io_setup (0+243)
#define __NR_io_destroy (0+244)
#define __NR_io_getevents (0+245)
#define __NR_io_submit (0+246)
#define __NR_io_cancel (0+247)
#define __NR_exit_group (0+248)
#define __NR_lookup_dcookie (0+249)
#define __NR_epoll_create (0+250)
#define __NR_epoll_ctl (0+251)
#define __NR_epoll_wait (0+252)
#define __NR_remap_file_pages (0+253)
#define __NR_set_tid_address (0+256)
#define __NR_timer_create (0+257)
#define __NR_timer_settime (0+258)
#define __NR_timer_gettime (0+259)
#define __NR_timer_getoverrun (0+260)
#define __NR_timer_delete (0+261)
#define __NR_clock_settime (0+262)
#define __NR_clock_gettime (0+263)
#define __NR_clock_getres (0+264)
#define __NR_clock_nanosleep (0+265)
#define __NR_statfs64 (0+266)
#define __NR_fstatfs64 (0+267)
#define __NR_tgkill (0+268)
#define __NR_utimes (0+269)
#define __NR_arm_fadvise64_64 (0+270)
#define __NR_pciconfig_iobase (0+271)
#define __NR_pciconfig_read (0+272)
#define __NR_pciconfig_write (0+273)
#define __NR_mq_open (0+274)
#define __NR_mq_unlink (0+275)
#define __NR_mq_timedsend (0+276)
#define __NR_mq_timedreceive (0+277)
#define __NR_mq_notify (0+278)
#define __NR_mq_getsetattr (0+279)
#define __NR_waitid (0+280)
#define __NR_socket (0+281)
#define __NR_bind (0+282)
#define __NR_connect (0+283)
#define __NR_listen (0+284)
#define __NR_accept (0+285)
#define __NR_getsockname (0+286)
#define __NR_getpeername (0+287)
#define __NR_socketpair (0+288)
#define __NR_send (0+289)
#define __NR_sendto (0+290)
#define __NR_recv (0+291)
#define __NR_recvfrom (0+292)
#define __NR_shutdown (0+293)
#define __NR_setsockopt (0+294)
#define __NR_getsockopt (0+295)
#define __NR_sendmsg (0+296)
#define __NR_recvmsg (0+297)
#define __NR_semop (0+298)
#define __NR_semget (0+299)
#define __NR_semctl (0+300)
#define __NR_msgsnd (0+301)
#define __NR_msgrcv (0+302)
#define __NR_msgget (0+303)
#define __NR_msgctl (0+304)
#define __NR_shmat (0+305)
#define __NR_shmdt (0+306)
#define __NR_shmget (0+307)
#define __NR_shmctl (0+308)
#define __NR_add_key (0+309)
#define __NR_request_key (0+310)
#define __NR_keyctl (0+311)
#define __NR_semtimedop (0+312)
#define __NR_vserver (0+313)
#define __NR_ioprio_set (0+314)
#define __NR_ioprio_get (0+315)
#define __NR_inotify_init (0+316)
#define __NR_inotify_add_watch (0+317)
#define __NR_inotify_rm_watch (0+318)
#define __NR_mbind (0+319)
#define __NR_get_mempolicy (0+320)
#define __NR_set_mempolicy (0+321)
#define __NR_openat (0+322)
#define __NR_mkdirat (0+323)
#define __NR_mknodat (0+324)
#define __NR_fchownat (0+325)
#define __NR_futimesat (0+326)
#define __NR_fstatat64 (0+327)
#define __NR_unlinkat (0+328)
#define __NR_renameat (0+329)
#define __NR_linkat (0+330)
#define __NR_symlinkat (0+331)
#define __NR_readlinkat (0+332)
#define __NR_fchmodat (0+333)
#define __NR_faccessat (0+334)
#define __NR_unshare (0+337)
#define __NR_set_robust_list (0+338)
#define __NR_get_robust_list (0+339)
#define __NR_splice (0+340)
#define __NR_arm_sync_file_range (0+341)
#define __NR_tee (0+342)
#define __NR_vmsplice (0+343)
#define __NR_move_pages (0+344)
#define __NR_getcpu (0+345)
#define __NR_kexec_load (0+347)
#define __NR_utimensat (0+348)
#define __NR_signalfd (0+349)
#define __NR_timerfd (0+350)
#define __NR_eventfd (0+351)
#define __NR_fallocate (0+352)
#define __NR_timerfd_settime (0+353)
#define __NR_timerfd_gettime (0+354)
#define __ARM_NR_BASE (0+0x0f0000)
#define __ARM_NR_breakpoint ((0+0x0f0000)+1)
#define __ARM_NR_cacheflush ((0+0x0f0000)+2)
#define __ARM_NR_usr26 ((0+0x0f0000)+3)
#define __ARM_NR_usr32 ((0+0x0f0000)+4)
#define __ARM_NR_set_tls ((0+0x0f0000)+5)
#define __ARGS_exit 0
#define __ARGS_fork 0
#define __ARGS_read 0
#define __ARGS_write 0
#define __ARGS_open 0
#define __ARGS_close 0
#define __ARGS_waitpid 0
#define __ARGS_creat 0
#define __ARGS_link 0
#define __ARGS_unlink 0
#define __ARGS_execve 0
#define __ARGS_chdir 0
#define __ARGS_time 0
#define __ARGS_mknod 0
#define __ARGS_chmod 0
#define __ARGS_lchown 0
#define __ARGS_break 0
#define __ARGS_lseek 0
#define __ARGS_getpid 0
#define __ARGS_mount 1
#define __ARGS_umount 0
#define __ARGS_setuid 0
#define __ARGS_getuid 0
#define __ARGS_stime 0
#define __ARGS_ptrace 0
#define __ARGS_alarm 0
#define __ARGS_pause 0
#define __ARGS_utime 0
#define __ARGS_stty 0
#define __ARGS_gtty 0
#define __ARGS_access 0
#define __ARGS_nice 0
#define __ARGS_ftime 0
#define __ARGS_sync 0
#define __ARGS_kill 0
#define __ARGS_rename 0
#define __ARGS_mkdir 0
#define __ARGS_rmdir 0
#define __ARGS_dup 0
#define __ARGS_pipe 0
#define __ARGS_times 0
#define __ARGS_prof 0
#define __ARGS_brk 0
#define __ARGS_setgid 0
#define __ARGS_getgid 0
#define __ARGS_signal 0
#define __ARGS_geteuid 0
#define __ARGS_getegid 0
#define __ARGS_acct 0
#define __ARGS_umount2 0
#define __ARGS_lock 0
#define __ARGS_ioctl 0
#define __ARGS_fcntl 0
#define __ARGS_mpx 0
#define __ARGS_setpgid 0
#define __ARGS_ulimit 0
#define __ARGS_umask 0
#define __ARGS_chroot 0
#define __ARGS_ustat 0
#define __ARGS_dup2 0
#define __ARGS_getppid 0
#define __ARGS_getpgrp 0
#define __ARGS_setsid 0
#define __ARGS_sigaction 0
#define __ARGS_sgetmask 0
#define __ARGS_ssetmask 0
#define __ARGS_setreuid 0
#define __ARGS_setregid 0
#define __ARGS_sigsuspend 0
#define __ARGS_sigpending 0
#define __ARGS_sethostname 0
#define __ARGS_setrlimit 0
#define __ARGS_getrlimit 0
#define __ARGS_getrusage 0
#define __ARGS_gettimeofday 0
#define __ARGS_settimeofday 0
#define __ARGS_getgroups 0
#define __ARGS_setgroups 0
#define __ARGS_select 0
#define __ARGS_symlink 0
#define __ARGS_readlink 0
#define __ARGS_uselib 0
#define __ARGS_swapon 0
#define __ARGS_reboot 0
#define __ARGS_readdir 0
#define __ARGS_mmap 0
#define __ARGS_munmap 0
#define __ARGS_truncate 0
#define __ARGS_ftruncate 0
#define __ARGS_fchmod 0
#define __ARGS_fchown 0
#define __ARGS_getpriority 0
#define __ARGS_setpriority 0
#define __ARGS_profil 0
#define __ARGS_statfs 0
#define __ARGS_fstatfs 0
#define __ARGS_ioperm 0
#define __ARGS_socketcall 0
#define __ARGS_syslog 0
#define __ARGS_setitimer 0
#define __ARGS_getitimer 0
#define __ARGS_stat 0
#define __ARGS_lstat 0
#define __ARGS_fstat 0
#define __ARGS_vhangup 0
#define __ARGS_idle 0
#define __ARGS_syscall 0
#define __ARGS_wait4 0
#define __ARGS_swapoff 0
#define __ARGS_sysinfo 0
#define __ARGS_ipc 1
#define __ARGS_fsync 0
#define __ARGS_sigreturn 0
#define __ARGS_clone 0
#define __ARGS_setdomainname 0
#define __ARGS_uname 0
#define __ARGS_modify_ldt 0
#define __ARGS_adjtimex 0
#define __ARGS_mprotect 0
#define __ARGS_sigprocmask 0
#define __ARGS_create_module 0
#define __ARGS_init_module 0
#define __ARGS_delete_module 0
#define __ARGS_get_kernel_syms 0
#define __ARGS_quotactl 0
#define __ARGS_getpgid 0
#define __ARGS_fchdir 0
#define __ARGS_bdflush 0
#define __ARGS_sysfs 0
#define __ARGS_personality 0
#define __ARGS_afs_syscall 0
#define __ARGS_setfsuid 0
#define __ARGS_setfsgid 0
#define __ARGS__llseek 1
#define __ARGS_getdents 0
#define __ARGS__newselect 1
#define __ARGS_flock 0
#define __ARGS_msync 0
#define __ARGS_readv 0
#define __ARGS_writev 0
#define __ARGS_getsid 0
#define __ARGS_fdatasync 0
#define __ARGS__sysctl 0
#define __ARGS_mlock 0
#define __ARGS_munlock 0
#define __ARGS_mlockall 0
#define __ARGS_munlockall 0
#define __ARGS_sched_setparam 0
#define __ARGS_sched_getparam 0
#define __ARGS_sched_setscheduler 0
#define __ARGS_sched_getscheduler 0
#define __ARGS_sched_yield 0
#define __ARGS_sched_get_priority_max 0
#define __ARGS_sched_get_priority_min 0
#define __ARGS_sched_rr_get_interval 0
#define __ARGS_nanosleep 0
#define __ARGS_mremap 0
#define __ARGS_setresuid 0
#define __ARGS_getresuid 0
#define __ARGS_vm86 0
#define __ARGS_query_module 1
#define __ARGS_poll 0
#define __ARGS_nfsservctl 0
#define __ARGS_setresgid 0
#define __ARGS_getresgid 0
#define __ARGS_prctl 1
#define __ARGS_rt_sigreturn 0
#define __ARGS_rt_sigaction 0
#define __ARGS_rt_sigprocmask 0
#define __ARGS_rt_sigpending 0
#define __ARGS_rt_sigtimedwait 0
#define __ARGS_rt_sigqueueinfo 0
#define __ARGS_rt_sigsuspend 0
#define __ARGS_pread 0
#define __ARGS_pwrite 0
#define __ARGS_pread64 0
#define __ARGS_pwrite64 0
#define __ARGS_chown 0
#define __ARGS_getcwd 0
#define __ARGS_capget 0
#define __ARGS_capset 0
#define __ARGS_sigaltstack 0
#define __ARGS_sendfile 0
#define __ARGS_vfork 0
#define __ARGS_ugetrlimit 0
#define __ARGS_mmap2 1
#define __ARGS_truncate64 0
#define __ARGS_ftruncate64 0
#define __ARGS_stat64 0
#define __ARGS_lstat64 0
#define __ARGS_fstat64 0
#define __ARGS_lchown32 0
#define __ARGS_getuid32 0
#define __ARGS_getgid32 0
#define __ARGS_geteuid32 0
#define __ARGS_getegid32 0
#define __ARGS_setreuid32 0
#define __ARGS_setregid32 0
#define __ARGS_getgroups32 0
#define __ARGS_setgroups32 0
#define __ARGS_fchown32 0
#define __ARGS_setresuid32 0
#define __ARGS_getresuid32 0
#define __ARGS_setresgid32 0
#define __ARGS_getresgid32 0
#define __ARGS_chown32 0
#define __ARGS_setuid32 0
#define __ARGS_setgid32 0
#define __ARGS_setfsuid32 0
#define __ARGS_setfsgid32 0
#define __ARGS_getdents64 0
#define __ARGS_pivot_root 0
#define __ARGS_mincore 0
#define __ARGS_madvise 0
#define __ARGS_fcntl64 0
#define __ARGS_security 0
#define __ARGS_gettid 0
#define __ARGS_readahead 0
#define __ARGS_setxattr 1
#define __ARGS_lsetxattr 1
#define __ARGS_fsetxattr 1
#define __ARGS_getxattr 0
#define __ARGS_lgetxattr 0
#define __ARGS_fgetxattr 0
#define __ARGS_listxattr 0
#define __ARGS_llistxattr 0
#define __ARGS_flistxattr 0
#define __ARGS_removexattr 0
#define __ARGS_lremovexattr 0
#define __ARGS_fremovexattr 0
#define __ARGS_tkill 0
#define __ARGS_sendfile64 0
#define __ARGS_futex 0
#define __ARGS_sched_setaffinity 0
#define __ARGS_sched_getaffinity 0
#define __ARGS_io_setup 0
#define __ARGS_io_destroy 0
#define __ARGS_io_getevents 0
#define __ARGS_io_submit 0
#define __ARGS_io_cancel 0
#define __ARGS_exit_group 0
#define __ARGS_lookup_dcookie 0
#define __ARGS_epoll_create 0
#define __ARGS_epoll_ctl 0
#define __ARGS_epoll_wait 0
#define __ARGS_remap_file_pages 0
#define __ARGS_set_thread_area 0
#define __ARGS_get_thread_area 0
#define __ARGS_set_tid_address 0
#define __ARGS_timer_create 0
#define __ARGS_timer_settime 0
#define __ARGS_timer_gettime 0
#define __ARGS_timer_getoverrun 0
#define __ARGS_timer_delete 0
#define __ARGS_clock_settime 0
#define __ARGS_clock_gettime 0
#define __ARGS_clock_getres 0
#define __ARGS_clock_nanosleep 0
#define __ARGS_statfs64 0
#define __ARGS_fstatfs64 0
#define __ARGS_tgkill 0
#define __ARGS_utimes 0
#define __ARGS_arm_fadvise64_64 1
#define __ARGS_fadvise64 0
#define __ARGS_fadvise64_64 0
#define __ARGS_pciconfig_iobase 0
#define __ARGS_pciconfig_read 1
#define __ARGS_pciconfig_write 1
#define __ARGS_mq_open 0
#define __ARGS_mq_unlink 0
#define __ARGS_mq_timedsend 0
#define __ARGS_mq_timedreceive 1
#define __ARGS_mq_notify 0
#define __ARGS_mq_getsetattr 0
#define __ARGS_waitid 0
#define __ARGS_socket 0
#define __ARGS_bind 0
#define __ARGS_connect 0
#define __ARGS_listen 0
#define __ARGS_accept 0
#define __ARGS_getsockname 0
#define __ARGS_getpeername 0
#define __ARGS_socketpair 0
#define __ARGS_send 0
#define __ARGS_sendto 0
#define __ARGS_recv 0
#define __ARGS_recvfrom 0
#define __ARGS_shutdown 0
#define __ARGS_setsockopt 0
#define __ARGS_getsockopt 0
#define __ARGS_sendmsg 0
#define __ARGS_recvmsg 0
#define __ARGS_semop 0
#define __ARGS_semget 0
#define __ARGS_semctl 0
#define __ARGS_msgsnd 0
#define __ARGS_msgrcv 0
#define __ARGS_msgget 0
#define __ARGS_msgctl 0
#define __ARGS_shmat 0
#define __ARGS_shmdt 0
#define __ARGS_shmget 0
#define __ARGS_shmctl 0
#define __ARGS_add_key 1
#define __ARGS_request_key 1
#define __ARGS_keyctl 0
#define __ARGS_vserver 0
#define __ARGS_ioprio_set 0
#define __ARGS_ioprio_get 0
#define __ARGS_inotify_init 0
#define __ARGS_inotify_add_watch 0
#define __ARGS_inotify_rm_watch 0
#define __ARGS_mbind 1
#define __ARGS_get_mempolicy 1
#define __ARGS_set_mempolicy 1
#define __ARGS_openat 0
#define __ARGS_mkdirat 0
#define __ARGS_mknodat 0
#define __ARGS_fchownat 1
#define __ARGS_futimesat 0
#define __ARGS_fstatat64 0
#define __ARGS_unlinkat 0
#define __ARGS_renameat 0
#define __ARGS_linkat 1
#define __ARGS_symlinkat 0
#define __ARGS_readlinkat 0
#define __ARGS_fchmodat 0
#define __ARGS_faccessat 0
#define __ARGS_unshare 0
#define __ARGS_set_robust_list 0
#define __ARGS_get_robust_list 0
#define __ARGS_splice 1
#define __ARGS_arm_sync_file_range 0
#define __ARGS_sync_file_range2 0
#define __ARGS_tee 0
#define __ARGS_vmsplice 0
#define __ARGS_move_pages 1
#define __ARGS_getcpu 0
#define __ARGS_kexec_load 0
#define __ARGS_utimensat 0
#define __ARGS_signalfd 0
#define __ARGS_timerfd 0
#define __ARGS_eventfd 0
#define __ARGS_fallocate 0
#define __ARGS_timerfd_settime 0
#define __ARGS_timerfd_gettime 0
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
#define EDEADLK 35
#define ENAMETOOLONG 36
#define ENOLCK 37
#define ENOSYS 38
#define ENOTEMPTY 39
#define ELOOP 40
#define EWOULDBLOCK 11
#define ENOMSG 42
#define EIDRM 43
#define ECHRNG 44
#define EL2NSYNC 45
#define EL3HLT 46
#define EL3RST 47
#define ELNRNG 48
#define EUNATCH 49
#define ENOCSI 50
#define EL2HLT 51
#define EBADE 52
#define EBADR 53
#define EXFULL 54
#define ENOANO 55
#define EBADRQC 56
#define EBADSLT 57
#define EDEADLOCK 35
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
#define EMULTIHOP 72
#define EDOTDOT 73
#define EBADMSG 74
#define EOVERFLOW 75
#define ENOTUNIQ 76
#define EBADFD 77
#define EREMCHG 78
#define ELIBACC 79
#define ELIBBAD 80
#define ELIBSCN 81
#define ELIBMAX 82
#define ELIBEXEC 83
#define EILSEQ 84
#define ERESTART 85
#define ESTRPIPE 86
#define EUSERS 87
#define ENOTSOCK 88
#define EDESTADDRREQ 89
#define EMSGSIZE 90
#define EPROTOTYPE 91
#define ENOPROTOOPT 92
#define EPROTONOSUPPORT 93
#define ESOCKTNOSUPPORT 94
#define EOPNOTSUPP 95
#define ENOTSUP 95
#define EPFNOSUPPORT 96
#define EAFNOSUPPORT 97
#define EADDRINUSE 98
#define EADDRNOTAVAIL 99
#define ENETDOWN 100
#define ENETUNREACH 101
#define ENETRESET 102
#define ECONNABORTED 103
#define ECONNRESET 104
#define ENOBUFS 105
#define EISCONN 106
#define ENOTCONN 107
#define ESHUTDOWN 108
#define ETOOMANYREFS 109
#define ETIMEDOUT 110
#define ECONNREFUSED 111
#define EHOSTDOWN 112
#define EHOSTUNREACH 113
#define EALREADY 114
#define EINPROGRESS 115
#define ESTALE 116
#define EUCLEAN 117
#define ENOTNAM 118
#define ENAVAIL 119
#define EISNAM 120
#define EREMOTEIO 121
#define EDQUOT 122
#define ENOMEDIUM 123
#define EMEDIUMTYPE 124
#define ECANCELED 125
#define ENOKEY 126
#define EKEYEXPIRED 127
#define EKEYREVOKED 128
#define EKEYREJECTED 129
#define __SYS_NERR ((129) + 1)
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __BYTE_ORDER 1234
#define __FLOAT_WORD_ORDER 1234
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define BYTE_ORDER 1234
#define __WORDSIZE 32
#define __FSUID_H 1
#define NSIG 32
#define _NSIG 64
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
#define SIGBUS 7
#define SIGUSR1 10
#define SIGUSR2 12
#define SIGSTKFLT 16
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG 23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGIO 29
#define SIGPWR 30
#define SIGSYS 31
#define SIGCLD 17
#define SIGPOLL 29
#define SIGLOST 30
#define SIGRTMIN 32
#define SIGRTMAX (64-1)
#define SA_NOCLDSTOP 0x00000001
#define SA_NOCLDWAIT 0x00000002
#define SA_SIGINFO 0x00000004
#define SA_THIRTYTWO 0x02000000
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
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2
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
#define STAT64_HAS_BROKEN_ST_INO 1
#define S_IFMT 0xf000
#define S_IFSOCK 0xc000
#define S_IFLNK 0xa000
#define S_IFREG 0x8000
#define S_IFBLK 0x6000
#define S_IFDIR 0x4000
#define S_IFCHR 0x2000
#define S_IFIFO 0x1000
#define S_ISUID 0x800
#define S_ISGID 0x400
#define S_ISVTX 0x200
#define S_IRWXU 0x1c0
#define S_IRUSR 0x100
#define S_IWUSR 0x80
#define S_IXUSR 0x40
#define S_IRWXG 0x38
#define S_IRGRP 0x20
#define S_IWGRP 0x10
#define S_IXGRP 0x8
#define S_IRWXO 0x7
#define S_IROTH 0x4
#define S_IWOTH 0x2
#define S_IXOTH 0x1
#define S_IREAD 0x100
#define S_IWRITE 0x80
#define S_IEXEC 0x40
#define F_LINUX_SPECIFIC_BASE 1024
#define O_ACCMODE 0x3
#define O_RDONLY 0x0
#define O_WRONLY 0x1
#define O_RDWR 0x2
#define O_CREAT 0x40
#define O_EXCL 0x80
#define O_NOCTTY 0x100
#define O_TRUNC 0x200
#define O_APPEND 0x400
#define O_NONBLOCK 0x800
#define O_NDELAY 0x800
#define O_SYNC 0x1000
#define FASYNC 0x2000
#define O_DIRECTORY 0x4000
#define O_NOFOLLOW 0x8000
#define O_DIRECT 0x10000
#define O_LARGEFILE 0x20000
#define O_NOATIME 0x40000
#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7
#define F_SETOWN 8
#define F_GETOWN 9
#define F_SETSIG 10
#define F_GETSIG 11
#define F_GETLK64 12
#define F_SETLK64 13
#define F_SETLKW64 14
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
#define O_ASYNC 0x2000
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define PROT_NONE 0x0
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_GROWSDOWN 0x0100
#define MAP_DENYWRITE 0x0800
#define MAP_EXECUTABLE 0x1000
#define MAP_LOCKED 0x2000
#define MAP_NORESERVE 0x4000
#define MAP_POPULATE 0x8000
#define MS_ASYNC 1
#define MS_INVALIDATE 2
#define MS_SYNC 4
#define MCL_CURRENT 1
#define MCL_FUTURE 2
#define MADV_NORMAL 0x0
#define MADV_RANDOM 0x1
#define MADV_SEQUENTIAL 0x2
#define MADV_WILLNEED 0x3
#define MADV_DONTNEED 0x4
#define MAP_ANON 0x20
#define MAP_FILE 0
#define SOL_SOCKET 1
#define SO_DEBUG 1
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_DONTROUTE 5
#define SO_BROADCAST 6
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_KEEPALIVE 9
#define SO_OOBINLINE 10
#define SO_NO_CHECK 11
#define SO_PRIORITY 12
#define SO_LINGER 13
#define SO_BSDCOMPAT 14
#define SO_PASSCRED 16
#define SO_PEERCRED 17
#define SO_RCVLOWAT 18
#define SO_SNDLOWAT 19
#define SO_RCVTIMEO 20
#define SO_SNDTIMEO 21
#define SO_ACCEPTCONN 30
#define SO_SNDBUFFORCE 32
#define SO_RCVBUFFORCE 33
#define SO_SECURITY_AUTHENTICATION 22
#define SO_SECURITY_ENCRYPTION_TRANSPORT 23
#define SO_SECURITY_ENCRYPTION_NETWORK 24
#define SO_BINDTODEVICE 25
#define SO_ATTACH_FILTER 26
#define SO_DETACH_FILTER 27
#define SO_PEERNAME 28
#define SO_TIMESTAMP 29
#define SCM_TIMESTAMP 29
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
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
#define USR26_MODE 0x00
#define FIQ26_MODE 0x01
#define IRQ26_MODE 0x02
#define SVC26_MODE 0x03
#define USR_MODE 0x10
#define FIQ_MODE 0x11
#define IRQ_MODE 0x12
#define SVC_MODE 0x13
#define ABT_MODE 0x17
#define UND_MODE 0x1b
#define SYSTEM_MODE 0x1f
#define MODE_MASK 0x1f
#define T_BIT 0x20
#define F_BIT 0x40
#define I_BIT 0x80
#define CC_V_BIT (1 << 28)
#define CC_C_BIT (1 << 29)
#define CC_Z_BIT (1 << 30)
#define CC_N_BIT (1 << 31)
#define PCMASK 0
#define SYS_accept (0+285)
#define SYS_access (0+ 33)
#define SYS_acct (0+ 51)
#define SYS_add_key (0+309)
#define SYS_adjtimex (0+124)
#define SYS_alarm (0+ 27)
#define SYS_arm_fadvise64_64 (0+270)
#define SYS_arm_sync_file_range (0+341)
#define SYS_bdflush (0+134)
#define SYS_bind (0+282)
#define SYS_brk (0+ 45)
#define SYS_capget (0+184)
#define SYS_capset (0+185)
#define SYS_chdir (0+ 12)
#define SYS_chmod (0+ 15)
#define SYS_chown (0+182)
#define SYS_chown32 (0+212)
#define SYS_chroot (0+ 61)
#define SYS_clock_getres (0+264)
#define SYS_clock_gettime (0+263)
#define SYS_clock_nanosleep (0+265)
#define SYS_clock_settime (0+262)
#define SYS_clone (0+120)
#define SYS_close (0+  6)
#define SYS_connect (0+283)
#define SYS_creat (0+  8)
#define SYS_delete_module (0+129)
#define SYS_dup (0+ 41)
#define SYS_dup2 (0+ 63)
#define SYS_epoll_create (0+250)
#define SYS_epoll_ctl (0+251)
#define SYS_epoll_wait (0+252)
#define SYS_eventfd (0+351)
#define SYS_execve (0+ 11)
#define SYS_exit (0+  1)
#define SYS_exit_group (0+248)
#define SYS_faccessat (0+334)
#define SYS_fallocate (0+352)
#define SYS_fchdir (0+133)
#define SYS_fchmod (0+ 94)
#define SYS_fchmodat (0+333)
#define SYS_fchown (0+ 95)
#define SYS_fchown32 (0+207)
#define SYS_fchownat (0+325)
#define SYS_fcntl (0+ 55)
#define SYS_fcntl64 (0+221)
#define SYS_fdatasync (0+148)
#define SYS_fgetxattr (0+231)
#define SYS_flistxattr (0+234)
#define SYS_flock (0+143)
#define SYS_fork (0+  2)
#define SYS_fremovexattr (0+237)
#define SYS_fsetxattr (0+228)
#define SYS_fstat (0+108)
#define SYS_fstat64 (0+197)
#define SYS_fstatat64 (0+327)
#define SYS_fstatfs (0+100)
#define SYS_fstatfs64 (0+267)
#define SYS_fsync (0+118)
#define SYS_ftruncate (0+ 93)
#define SYS_ftruncate64 (0+194)
#define SYS_futex (0+240)
#define SYS_futimesat (0+326)
#define SYS_getcpu (0+345)
#define SYS_getcwd (0+183)
#define SYS_getdents (0+141)
#define SYS_getdents64 (0+217)
#define SYS_getegid (0+ 50)
#define SYS_getegid32 (0+202)
#define SYS_geteuid (0+ 49)
#define SYS_geteuid32 (0+201)
#define SYS_getgid (0+ 47)
#define SYS_getgid32 (0+200)
#define SYS_getgroups (0+ 80)
#define SYS_getgroups32 (0+205)
#define SYS_getitimer (0+105)
#define SYS_get_mempolicy (0+320)
#define SYS_getpeername (0+287)
#define SYS_getpgid (0+132)
#define SYS_getpgrp (0+ 65)
#define SYS_getpid (0+ 20)
#define SYS_getppid (0+ 64)
#define SYS_getpriority (0+ 96)
#define SYS_getresgid (0+171)
#define SYS_getresgid32 (0+211)
#define SYS_getresuid (0+165)
#define SYS_getresuid32 (0+209)
#define SYS_getrlimit (0+ 76)
#define SYS_get_robust_list (0+339)
#define SYS_getrusage (0+ 77)
#define SYS_getsid (0+147)
#define SYS_getsockname (0+286)
#define SYS_getsockopt (0+295)
#define SYS_gettid (0+224)
#define SYS_gettimeofday (0+ 78)
#define SYS_getuid (0+ 24)
#define SYS_getuid32 (0+199)
#define SYS_getxattr (0+229)
#define SYS_init_module (0+128)
#define SYS_inotify_add_watch (0+317)
#define SYS_inotify_init (0+316)
#define SYS_inotify_rm_watch (0+318)
#define SYS_io_cancel (0+247)
#define SYS_ioctl (0+ 54)
#define SYS_io_destroy (0+244)
#define SYS_io_getevents (0+245)
#define SYS_ioprio_get (0+315)
#define SYS_ioprio_set (0+314)
#define SYS_io_setup (0+243)
#define SYS_io_submit (0+246)
#define SYS_ipc (0+117)
#define SYS_kexec_load (0+347)
#define SYS_keyctl (0+311)
#define SYS_kill (0+ 37)
#define SYS_lchown (0+ 16)
#define SYS_lchown32 (0+198)
#define SYS_lgetxattr (0+230)
#define SYS_link (0+  9)
#define SYS_linkat (0+330)
#define SYS_listen (0+284)
#define SYS_listxattr (0+232)
#define SYS_llistxattr (0+233)
#define SYS__llseek (0+140)
#define SYS_lookup_dcookie (0+249)
#define SYS_lremovexattr (0+236)
#define SYS_lseek (0+ 19)
#define SYS_lsetxattr (0+227)
#define SYS_lstat (0+107)
#define SYS_lstat64 (0+196)
#define SYS_madvise (0+220)
#define SYS_mbind (0+319)
#define SYS_mincore (0+219)
#define SYS_mkdir (0+ 39)
#define SYS_mkdirat (0+323)
#define SYS_mknod (0+ 14)
#define SYS_mknodat (0+324)
#define SYS_mlock (0+150)
#define SYS_mlockall (0+152)
#define SYS_mmap (0+ 90)
#define SYS_mmap2 (0+192)
#define SYS_mount (0+ 21)
#define SYS_move_pages (0+344)
#define SYS_mprotect (0+125)
#define SYS_mq_getsetattr (0+279)
#define SYS_mq_notify (0+278)
#define SYS_mq_open (0+274)
#define SYS_mq_timedreceive (0+277)
#define SYS_mq_timedsend (0+276)
#define SYS_mq_unlink (0+275)
#define SYS_mremap (0+163)
#define SYS_msgctl (0+304)
#define SYS_msgget (0+303)
#define SYS_msgrcv (0+302)
#define SYS_msgsnd (0+301)
#define SYS_msync (0+144)
#define SYS_munlock (0+151)
#define SYS_munlockall (0+153)
#define SYS_munmap (0+ 91)
#define SYS_nanosleep (0+162)
#define SYS__newselect (0+142)
#define SYS_nfsservctl (0+169)
#define SYS_nice (0+ 34)
#define SYS_OABI_SYSCALL_BASE 0x900000
#define SYS_open (0+  5)
#define SYS_openat (0+322)
#define SYS_pause (0+ 29)
#define SYS_pciconfig_iobase (0+271)
#define SYS_pciconfig_read (0+272)
#define SYS_pciconfig_write (0+273)
#define SYS_personality (0+136)
#define SYS_pipe (0+ 42)
#define SYS_pivot_root (0+218)
#define SYS_poll (0+168)
#define SYS_prctl (0+172)
#define SYS_pread64 (0+180)
#define SYS_ptrace (0+ 26)
#define SYS_pwrite64 (0+181)
#define SYS_quotactl (0+131)
#define SYS_read (0+  3)
#define SYS_readahead (0+225)
#define SYS_readdir (0+ 89)
#define SYS_readlink (0+ 85)
#define SYS_readlinkat (0+332)
#define SYS_readv (0+145)
#define SYS_reboot (0+ 88)
#define SYS_recv (0+291)
#define SYS_recvfrom (0+292)
#define SYS_recvmsg (0+297)
#define SYS_remap_file_pages (0+253)
#define SYS_removexattr (0+235)
#define SYS_rename (0+ 38)
#define SYS_renameat (0+329)
#define SYS_request_key (0+310)
#define SYS_restart_syscall (0+  0)
#define SYS_rmdir (0+ 40)
#define SYS_rt_sigaction (0+174)
#define SYS_rt_sigpending (0+176)
#define SYS_rt_sigprocmask (0+175)
#define SYS_rt_sigqueueinfo (0+178)
#define SYS_rt_sigreturn (0+173)
#define SYS_rt_sigsuspend (0+179)
#define SYS_rt_sigtimedwait (0+177)
#define SYS_sched_getaffinity (0+242)
#define SYS_sched_getparam (0+155)
#define SYS_sched_get_priority_max (0+159)
#define SYS_sched_get_priority_min (0+160)
#define SYS_sched_getscheduler (0+157)
#define SYS_sched_rr_get_interval (0+161)
#define SYS_sched_setaffinity (0+241)
#define SYS_sched_setparam (0+154)
#define SYS_sched_setscheduler (0+156)
#define SYS_sched_yield (0+158)
#define SYS_select (0+ 82)
#define SYS_semctl (0+300)
#define SYS_semget (0+299)
#define SYS_semop (0+298)
#define SYS_semtimedop (0+312)
#define SYS_send (0+289)
#define SYS_sendfile (0+187)
#define SYS_sendfile64 (0+239)
#define SYS_sendmsg (0+296)
#define SYS_sendto (0+290)
#define SYS_setdomainname (0+121)
#define SYS_setfsgid (0+139)
#define SYS_setfsgid32 (0+216)
#define SYS_setfsuid (0+138)
#define SYS_setfsuid32 (0+215)
#define SYS_setgid (0+ 46)
#define SYS_setgid32 (0+214)
#define SYS_setgroups (0+ 81)
#define SYS_setgroups32 (0+206)
#define SYS_sethostname (0+ 74)
#define SYS_setitimer (0+104)
#define SYS_set_mempolicy (0+321)
#define SYS_setpgid (0+ 57)
#define SYS_setpriority (0+ 97)
#define SYS_setregid (0+ 71)
#define SYS_setregid32 (0+204)
#define SYS_setresgid (0+170)
#define SYS_setresgid32 (0+210)
#define SYS_setresuid (0+164)
#define SYS_setresuid32 (0+208)
#define SYS_setreuid (0+ 70)
#define SYS_setreuid32 (0+203)
#define SYS_setrlimit (0+ 75)
#define SYS_set_robust_list (0+338)
#define SYS_setsid (0+ 66)
#define SYS_setsockopt (0+294)
#define SYS_set_tid_address (0+256)
#define SYS_settimeofday (0+ 79)
#define SYS_setuid (0+ 23)
#define SYS_setuid32 (0+213)
#define SYS_setxattr (0+226)
#define SYS_shmat (0+305)
#define SYS_shmctl (0+308)
#define SYS_shmdt (0+306)
#define SYS_shmget (0+307)
#define SYS_shutdown (0+293)
#define SYS_sigaction (0+ 67)
#define SYS_sigaltstack (0+186)
#define SYS_signalfd (0+349)
#define SYS_sigpending (0+ 73)
#define SYS_sigprocmask (0+126)
#define SYS_sigreturn (0+119)
#define SYS_sigsuspend (0+ 72)
#define SYS_socket (0+281)
#define SYS_socketcall (0+102)
#define SYS_socketpair (0+288)
#define SYS_splice (0+340)
#define SYS_stat (0+106)
#define SYS_stat64 (0+195)
#define SYS_statfs (0+ 99)
#define SYS_statfs64 (0+266)
#define SYS_stime (0+ 25)
#define SYS_swapoff (0+115)
#define SYS_swapon (0+ 87)
#define SYS_symlink (0+ 83)
#define SYS_symlinkat (0+331)
#define SYS_sync (0+ 36)
#define SYS_syscall (0+113)
#define SYS_SYSCALL_BASE 0
#define SYS__sysctl (0+149)
#define SYS_sysfs (0+135)
#define SYS_sysinfo (0+116)
#define SYS_syslog (0+103)
#define SYS_tee (0+342)
#define SYS_tgkill (0+268)
#define SYS_time (0+ 13)
#define SYS_timer_create (0+257)
#define SYS_timer_delete (0+261)
#define SYS_timerfd (0+350)
#define SYS_timerfd_gettime (0+354)
#define SYS_timerfd_settime (0+353)
#define SYS_timer_getoverrun (0+260)
#define SYS_timer_gettime (0+259)
#define SYS_timer_settime (0+258)
#define SYS_times (0+ 43)
#define SYS_tkill (0+238)
#define SYS_truncate (0+ 92)
#define SYS_truncate64 (0+193)
#define SYS_ugetrlimit (0+191)
#define SYS_umask (0+ 60)
#define SYS_umount (0+ 22)
#define SYS_umount2 (0+ 52)
#define SYS_uname (0+122)
#define SYS_unlink (0+ 10)
#define SYS_unlinkat (0+328)
#define SYS_unshare (0+337)
#define SYS_uselib (0+ 86)
#define SYS_ustat (0+ 62)
#define SYS_utime (0+ 30)
#define SYS_utimensat (0+348)
#define SYS_utimes (0+269)
#define SYS_vfork (0+190)
#define SYS_vhangup (0+111)
#define SYS_vmsplice (0+343)
#define SYS_vserver (0+313)
#define SYS_wait4 (0+114)
#define SYS_waitid (0+280)
#define SYS_write (0+  4)
#define SYS_writev (0+146)
