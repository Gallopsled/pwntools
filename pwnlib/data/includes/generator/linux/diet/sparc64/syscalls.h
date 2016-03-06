
#define __NR_exit                 1 /* Common                                      */
#define __NR_fork                 2 /* Common                                      */
#define __NR_read                 3 /* Common                                      */
#define __NR_write                4 /* Common                                      */
#define __NR_open                 5 /* Common                                      */
#define __NR_close                6 /* Common                                      */
#define __NR_wait4                7 /* Common                                      */
#define __NR_creat                8 /* Common                                      */
#define __NR_link                 9 /* Common                                      */
#define __NR_unlink              10 /* Common                                      */
#define __NR_execv               11 /* SunOS Specific                              */
#define __NR_chdir               12 /* Common                                      */
#define __NR_chown		 13 /* Common					   */
#define __NR_mknod               14 /* Common                                      */
#define __NR_chmod               15 /* Common                                      */
#define __NR_lchown              16 /* Common                                      */
#define __NR_brk                 17 /* Common                                      */
#define __NR_perfctr             18 /* Performance counter operations              */
#define __NR_lseek               19 /* Common                                      */
#define __NR_getpid              20 /* Common                                      */
#define __NR_capget		 21 /* Linux Specific				   */
#define __NR_capset		 22 /* Linux Specific				   */
#define __NR_setuid              23 /* Implemented via setreuid in SunOS           */
#define __NR_getuid              24 /* Common                                      */
/* #define __NR_time alias	 25    ENOSYS under SunOS			   */
#define __NR_ptrace              26 /* Common                                      */
#define __NR_alarm               27 /* Implemented via setitimer in SunOS          */
#define __NR_sigaltstack	 28 /* Common					   */
#define __NR_pause               29 /* Is sigblock(0)->sigpause() in SunOS         */
#define __NR_utime               30 /* Implemented via utimes() under SunOS        */
/* #define __NR_lchown32         31    Linux sparc32 specific                      */
/* #define __NR_fchown32         32    Linux sparc32 specific                      */
#define __NR_access              33 /* Common                                      */
#define __NR_nice                34 /* Implemented via get/setpriority() in SunOS  */
/* #define __NR_chown32          35    Linux sparc32 specific                      */
#define __NR_sync                36 /* Common                                      */
#define __NR_kill                37 /* Common                                      */
#define __NR_stat                38 /* Common                                      */
#define __NR_sendfile		 39 /* Linux Specific				   */
#define __NR_lstat               40 /* Common                                      */
#define __NR_dup                 41 /* Common                                      */
#define __NR_pipe                42 /* Common                                      */
#define __NR_times               43 /* Implemented via getrusage() in SunOS        */
/* #define __NR_getuid32         44    Linux sparc32 specific                      */
#define __NR_umount2             45 /* Linux Specific                              */
#define __NR_setgid              46 /* Implemented via setregid() in SunOS         */
#define __NR_getgid              47 /* Common                                      */
#define __NR_signal              48 /* Implemented via sigvec() in SunOS           */
#define __NR_geteuid             49 /* SunOS calls getuid()                        */
#define __NR_getegid             50 /* SunOS calls getgid()                        */
#define __NR_acct                51 /* Common                                      */
#define __NR_memory_ordering	 52 /* Linux Specific				   */
/* #define __NR_getgid32         53    Linux sparc32 specific                      */
#define __NR_ioctl               54 /* Common                                      */
#define __NR_reboot              55 /* Common                                      */
/* #define __NR_mmap2		 56    Linux sparc32 Specific                      */
#define __NR_symlink             57 /* Common                                      */
#define __NR_readlink            58 /* Common                                      */
#define __NR_execve              59 /* Common                                      */
#define __NR_umask               60 /* Common                                      */
#define __NR_chroot              61 /* Common                                      */
#define __NR_fstat               62 /* Common                                      */
/* #define __NR_fstat64          63    Linux sparc32 Specific                      */
#define __NR_getpagesize         64 /* Common                                      */
#define __NR_msync               65 /* Common in newer 1.3.x revs...               */
#define __NR_vfork               66 /* Common                                      */
#define __NR_pread               67 /* Linux Specific                              */
#define __NR_pwrite              68 /* Linux Specific                              */
/* #define __NR_geteuid32        69    Linux sparc32, sbrk under SunOS             */
/* #define __NR_getegid32        70    Linux sparc32, sstk under SunOS             */
#define __NR_mmap                71 /* Common                                      */
/* #define __NR_setreuid32       72    Linux sparc32, vadvise under SunOS          */
#define __NR_munmap              73 /* Common                                      */
#define __NR_mprotect            74 /* Common                                      */
#define __NR_madvise             75 /* Common                                      */
#define __NR_vhangup             76 /* Common                                      */
/* #define __NR_truncate64       77    Linux sparc32 Specific			   */
#define __NR_mincore             78 /* Common                                      */
#define __NR_getgroups           79 /* Common                                      */
#define __NR_setgroups           80 /* Common                                      */
#define __NR_getpgrp             81 /* Common                                      */
/* #define __NR_setgroups32      82    Linux sparc32, setpgrp under SunOS          */
#define __NR_setitimer           83 /* Common                                      */
/* #define __NR_ftruncate64      84    Linux sparc32 Specific			   */
#define __NR_swapon              85 /* Common                                      */
#define __NR_getitimer           86 /* Common                                      */
/* #define __NR_setuid32         87    Linux sparc32, gethostname under SunOS      */
#define __NR_sethostname         88 /* Common                                      */
/* #define __NR_setgid32         89    Linux sparc32, getdtablesize under SunOS    */
#define __NR_dup2                90 /* Common                                      */
/* #define __NR_setfsuid32       91    Linux sparc32, getdopt under SunOS          */
#define __NR_fcntl               92 /* Common                                      */
#define __NR_select              93 /* Common                                      */
/* #define __NR_setfsgid32       94    Linux sparc32, setdopt under SunOS          */
#define __NR_fsync               95 /* Common                                      */
#define __NR_setpriority         96 /* Common                                      */
#define __NR_socket              97 /* Common                                      */
#define __NR_connect             98 /* Common                                      */
#define __NR_accept              99 /* Common                                      */
#define __NR_getpriority        100 /* Common                                      */
#define __NR_rt_sigreturn       101 /* Linux Specific                              */
#define __NR_rt_sigaction       102 /* Linux Specific                              */
#define __NR_rt_sigprocmask     103 /* Linux Specific                              */
#define __NR_rt_sigpending      104 /* Linux Specific                              */
#define __NR_rt_sigtimedwait    105 /* Linux Specific                              */
#define __NR_rt_sigqueueinfo    106 /* Linux Specific                              */
#define __NR_rt_sigsuspend      107 /* Linux Specific                              */
#define __NR_setresuid          108 /* Linux Specific, sigvec under SunOS	   */
#define __NR_getresuid          109 /* Linux Specific, sigblock under SunOS	   */
#define __NR_setresgid          110 /* Linux Specific, sigsetmask under SunOS	   */
#define __NR_getresgid          111 /* Linux Specific, sigpause under SunOS	   */
/* #define __NR_setregid32       75    Linux sparc32, sigstack under SunOS         */
#define __NR_recvmsg            113 /* Common                                      */
#define __NR_sendmsg            114 /* Common                                      */
/* #define __NR_getgroups32     115    Linux sparc32, vtrace under SunOS           */
#define __NR_gettimeofday       116 /* Common                                      */
#define __NR_getrusage          117 /* Common                                      */
#define __NR_getsockopt         118 /* Common                                      */
#define __NR_getcwd		119 /* Linux Specific				   */
#define __NR_readv              120 /* Common                                      */
#define __NR_writev             121 /* Common                                      */
#define __NR_settimeofday       122 /* Common                                      */
#define __NR_fchown             123 /* Common                                      */
#define __NR_fchmod             124 /* Common                                      */
#define __NR_recvfrom           125 /* Common                                      */
#define __NR_setreuid           126 /* Common                                      */
#define __NR_setregid           127 /* Common                                      */
#define __NR_rename             128 /* Common                                      */
#define __NR_truncate           129 /* Common                                      */
#define __NR_ftruncate          130 /* Common                                      */
#define __NR_flock              131 /* Common                                      */
/* #define __NR_lstat64		132    Linux sparc32 Specific                      */
#define __NR_sendto             133 /* Common                                      */
#define __NR_shutdown           134 /* Common                                      */
#define __NR_socketpair         135 /* Common                                      */
#define __NR_mkdir              136 /* Common                                      */
#define __NR_rmdir              137 /* Common                                      */
#define __NR_utimes             138 /* SunOS Specific                              */
/* #define __NR_stat64		139    Linux sparc32 Specific			   */
#define __NR_sendfile64         140 /* adjtime under SunOS                         */
#define __NR_getpeername        141 /* Common                                      */
#define __NR_futex              142 /* gethostid under SunOS                       */
#define __NR_gettid             143 /* ENOSYS under SunOS                          */
#define __NR_getrlimit		144 /* Common                                      */
#define __NR_setrlimit          145 /* Common                                      */
#define __NR_pivot_root		146 /* Linux Specific, killpg under SunOS          */
#define __NR_prctl		147 /* ENOSYS under SunOS                          */
#define __NR_pciconfig_read	148 /* ENOSYS under SunOS                          */
#define __NR_pciconfig_write	149 /* ENOSYS under SunOS                          */
#define __NR_getsockname        150 /* Common                                      */
/* #define __NR_getmsg          151    SunOS Specific                              */
/* #define __NR_putmsg          152    SunOS Specific                              */
#define __NR_poll               153 /* Common                                      */
#define __NR_getdents64		154 /* Linux specific				   */
/* #define __NR_fcntl64         155    Linux sparc32 Specific                      */
/* #define __NR_getdirentries   156    SunOS Specific                              */
#define __NR_statfs             157 /* Common                                      */
#define __NR_fstatfs            158 /* Common                                      */
#define __NR_umount             159 /* Common                                      */
#define __NR_sched_set_affinity 160 /* Linux specific, async_daemon under SunOS    */
#define __NR_sched_get_affinity 161 /* Linux specific, getfh under SunOS           */
#define __NR_getdomainname      162 /* SunOS Specific                              */
#define __NR_setdomainname      163 /* Common                                      */
#define __NR_utrap_install	164 /* SYSV ABI/v9 required			   */
#define __NR_quotactl           165 /* Common                                      */
#define __NR_set_tid_address    166 /* Linux specific, exportfs under SunOS        */
#define __NR_mount              167 /* Common                                      */
#define __NR_ustat              168 /* Common                                      */
#define __NR_setxattr           169 /* SunOS: semsys                               */
#define __NR_lsetxattr          170 /* SunOS: msgsys                               */
#define __NR_fsetxattr          171 /* SunOS: shmsys                               */
#define __NR_getxattr           172 /* SunOS: auditsys                             */
#define __NR_lgetxattr          173 /* SunOS: rfssys                               */
#define __NR_getdents           174 /* Common                                      */
#define __NR_setsid             175 /* Common                                      */
#define __NR_fchdir             176 /* Common                                      */
#define __NR_fgetxattr          177 /* SunOS: fchroot                              */
#define __NR_listxattr          178 /* SunOS: vpixsys                              */
#define __NR_llistxattr         179 /* SunOS: aioread                              */
#define __NR_flistxattr         180 /* SunOS: aiowrite                             */
#define __NR_removexattr        181 /* SunOS: aiowait                              */
#define __NR_lremovexattr       182 /* SunOS: aiocancel                            */
#define __NR_sigpending         183 /* Common                                      */
#define __NR_query_module	184 /* Linux Specific				   */
#define __NR_setpgid            185 /* Common                                      */
#define __NR_fremovexattr       186 /* SunOS: pathconf                             */
#define __NR_tkill              187 /* SunOS: fpathconf                            */
#define __NR_exit_group		188 /* Linux specific, sysconf undef SunOS         */
#define __NR_uname              189 /* Linux Specific                              */
#define __NR_init_module        190 /* Linux Specific                              */
#define __NR_personality        191 /* Linux Specific                              */
#define __NR_remap_file_pages   192 /* Linux Specific                              */
#define __NR_epoll_create       193 /* Linux Specific                              */
#define __NR_epoll_ctl          194 /* Linux Specific                              */
#define __NR_epoll_wait         195 /* Linux Specific                              */
/* #define __NR_ulimit          196    Linux Specific                              */
#define __NR_getppid            197 /* Linux Specific                              */
#define __NR_sigaction          198 /* Linux Specific                              */
#define __NR_sgetmask           199 /* Linux Specific                              */
#define __NR_ssetmask           200 /* Linux Specific                              */
#define __NR_sigsuspend         201 /* Linux Specific                              */
#define __NR_oldlstat           202 /* Linux Specific                              */
#define __NR_uselib             203 /* Linux Specific                              */
#define __NR_readdir            204 /* Linux Specific                              */
#define __NR_readahead          205 /* Linux Specific                              */
#define __NR_socketcall         206 /* Linux Specific                              */
#define __NR_syslog             207 /* Linux Specific                              */
#define __NR_lookup_dcookie     208 /* Linux Specific                              */
#define __NR_fadvise64          209 /* Linux Specific                              */
#define __NR_fadvise64_64       210 /* Linux Specific                              */
#define __NR_tgkill             211 /* Linux Specific                              */
#define __NR_waitpid            212 /* Linux Specific                              */
#define __NR_swapoff            213 /* Linux Specific                              */
#define __NR_sysinfo            214 /* Linux Specific                              */
#define __NR_ipc                215 /* Linux Specific                              */
#define __NR_sigreturn          216 /* Linux Specific                              */
#define __NR_clone              217 /* Linux Specific                              */
/* #define __NR_modify_ldt      218    Linux Specific - i386 specific, unused      */
#define __NR_adjtimex           219 /* Linux Specific                              */
#define __NR_sigprocmask        220 /* Linux Specific                              */
#define __NR_create_module      221 /* Linux Specific                              */
#define __NR_delete_module      222 /* Linux Specific                              */
#define __NR_get_kernel_syms    223 /* Linux Specific                              */
#define __NR_getpgid            224 /* Linux Specific                              */
#define __NR_bdflush            225 /* Linux Specific                              */
#define __NR_sysfs              226 /* Linux Specific                              */
#define __NR_afs_syscall        227 /* Linux Specific                              */
#define __NR_setfsuid           228 /* Linux Specific                              */
#define __NR_setfsgid           229 /* Linux Specific                              */
#define __NR__newselect         230 /* Linux Specific                              */
/* #define __NR_oldstat         232    Linux Specific                              */
#define __NR_stime              233 /* Linux Specific                              */
#define __NR_statfs64           234 /* Linux Specific                              */
#define __NR_fstatfs64          235 /* Linux Specific                              */
#define __NR__llseek            236 /* Linux Specific                              */
#define __NR_mlock              237
#define __NR_munlock            238
#define __NR_mlockall           239
#define __NR_munlockall         240
#define __NR_sched_setparam     241
#define __NR_sched_getparam     242
#define __NR_sched_setscheduler 243
#define __NR_sched_getscheduler 244
#define __NR_sched_yield        245
#define __NR_sched_get_priority_max 246
#define __NR_sched_get_priority_min 247
#define __NR_sched_rr_get_interval  248
#define __NR_nanosleep          249
#define __NR_mremap             250
#define __NR__sysctl            251
#define __NR_getsid             252
#define __NR_fdatasync          253
#define __NR_nfsservctl         254
#define __NR_aplib              255
#define __NR_clock_settime	256
#define __NR_clock_gettime	257
#define __NR_clock_getres	258
#define __NR_clock_nanosleep	259
#define __NR_sched_getaffinity	260
#define __NR_sched_setaffinity	261
#define __NR_timer_settime	262
#define __NR_timer_gettime	263
#define __NR_timer_getoverrun	264
#define __NR_timer_delete	265
#define __NR_timer_create	266
/* #define __NR_vserver		267 Reserved for VSERVER */
#define __NR_io_setup		268
#define __NR_io_destroy		269
#define __NR_io_submit		270
#define __NR_io_cancel		271
#define __NR_io_getevents	272
#define __NR_mq_open		273
#define __NR_mq_unlink		274
#define __NR_mq_timedsend	275
#define __NR_mq_timedreceive	276
#define __NR_mq_notify		277
#define __NR_mq_getsetattr	278
#define __NR_waitid		279
/*#define __NR_sys_setaltroot	280 available (was setaltroot) */
#define __NR_add_key		281
#define __NR_request_key	282
#define __NR_keyctl		283
#define __NR_openat		284
#define __NR_mkdirat		285
#define __NR_mknodat		286
#define __NR_fchownat		287
#define __NR_futimesat		288
#define __NR_fstatat64		289
#define __NR_unlinkat		290
#define __NR_renameat		291
#define __NR_linkat		292
#define __NR_symlinkat		293
#define __NR_readlinkat		294
#define __NR_fchmodat		295
#define __NR_faccessat		296
#define __NR_pselect6		297
#define __NR_ppoll		298
#define __NR_unshare		299
#define __NR_set_robust_list	300
#define __NR_get_robust_list	301
#define __NR_migrate_pages	302
#define __NR_mbind		303
#define __NR_get_mempolicy	304
#define __NR_set_mempolicy	305
#define __NR_kexec_load		306
#define __NR_move_pages		307
#define __NR_getcpu		308
#define __NR_epoll_pwait	309
#define __NR_utimensat		310
#define __NR_signalfd		311
#define __NR_timerfd		312
#define __NR_eventfd		313
#define __NR_fallocate		314
#define __NR_timerfd_settime	315
#define __NR_timerfd_gettime	316

#define syscall_weak(name,wsym,sym) \
.text; \
.type wsym,function; \
.weak wsym; \
wsym: ; \
.type sym,function; \
.global sym; \
sym: \
	b __unified_syscall; \
	mov __NR_##name, %g1

#define syscall(name,sym) \
.text; \
.type sym,function; \
.global sym; \
sym: \
	b __unified_syscall; \
	mov __NR_##name, %g1

