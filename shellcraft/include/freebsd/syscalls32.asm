%define SYS_syscall   0
%define SYS_exit      1
%define SYS_fork      2
%define SYS_read      3
%define SYS_write     4
%define SYS_freebsd32_open    5
%define SYS_close     6
%define SYS_freebsd32_wait4   7
                                ; 8 is obsolete old creat */
%define SYS_link      9
%define SYS_unlink    10
                                ; 11 is obsolete execv */
%define SYS_chdir     12
%define SYS_fchdir    13
%define SYS_mknod     14
%define SYS_chmod     15
%define SYS_chown     16
%define SYS_break     17
%define SYS_freebsd32_getfsstat       18
                                ; 19 is obsolete olseek */
%define SYS_getpid    20
%define SYS_mount     21
%define SYS_unmount   22
%define SYS_setuid    23
%define SYS_getuid    24
%define SYS_geteuid   25
%define SYS_ptrace    26
%define SYS_sendmsg   28
%define SYS_recvfrom  29
%define SYS_accept    30
%define SYS_getpeername       31
%define SYS_getsockname       32
%define SYS_freebsd32_access  33
%define SYS_freebsd32_chflags 34
%define SYS_fchflags  35
%define SYS_sync      36
%define SYS_kill      37
%define SYS_getppid   39
%define SYS_dup       41
%define SYS_pipe      42
%define SYS_getegid   43
%define SYS_profil    44
%define SYS_ktrace    45
%define SYS_getgid    47
%define SYS_getlogin  49
%define SYS_setlogin  50
%define SYS_acct      51
                                ; 52 is obsolete osigpending */
%define SYS_freebsd32_sigaltstack     53
%define SYS_ioctl     54
%define SYS_reboot    55
%define SYS_revoke    56
%define SYS_symlink   57
%define SYS_readlink  58
%define SYS_execve    59
%define SYS_umask     60
%define SYS_chroot    61
                                ; 62 is obsolete ofstat */
                                ; 63 is obsolete ogetkerninfo */
                                ; 64 is obsolete ogetpagesize */
                                ; 65 is obsolete omsync */
%define SYS_vfork     66
                                ; 67 is obsolete vread */
                                ; 68 is obsolete vwrite */
%define SYS_sbrk      69
%define SYS_sstk      70
                                ; 71 is obsolete ommap */
%define SYS_vadvise   72
%define SYS_munmap    73
%define SYS_mprotect  74
%define SYS_madvise   75
                                ; 76 is obsolete vhangup */
                                ; 77 is obsolete vlimit */
%define SYS_mincore   78
%define SYS_getgroups 79
%define SYS_setgroups 80
%define SYS_getpgrp   81
%define SYS_setpgid   82
%define SYS_freebsd32_setitimer       83
                                ; 84 is obsolete owait */
                                ; 85 is obsolete oswapon */
                                ; 86 is obsolete ogetitimer */
                                ; 87 is obsolete ogethostname */
                                ; 88 is obsolete osethostname */
%define SYS_getdtablesize     89
%define SYS_dup2      90
%define SYS_fcntl     92
%define SYS_freebsd32_select  93
%define SYS_fsync     95
%define SYS_setpriority       96
%define SYS_socket    97
%define SYS_connect   98
                                ; 99 is obsolete oaccept */
%define SYS_getpriority       100
                                ; 101 is obsolete osend */
                                ; 102 is obsolete orecv */
                                ; 103 is obsolete osigreturn */
%define SYS_bind      104
%define SYS_setsockopt        105
%define SYS_listen    106
                                ; 107 is obsolete vtimes */
                                ; 108 is obsolete osigvec */
                                ; 109 is obsolete osigblock */
                                ; 110 is obsolete osigsetmask */
                                ; 111 is obsolete osigsuspend */
                                ; 112 is obsolete osigstack */
                                ; 113 is obsolete orecvmsg */
                                ; 114 is obsolete osendmsg */
                                ; 115 is obsolete vtrace */
%define SYS_freebsd32_gettimeofday    116
%define SYS_freebsd32_getrusage       117
%define SYS_getsockopt        118
%define SYS_freebsd32_readv   120
%define SYS_freebsd32_writev  121
%define SYS_freebsd32_settimeofday    122
%define SYS_fchown    123
%define SYS_fchmod    124
                                ; 125 is obsolete orecvfrom */
%define SYS_setreuid  126
%define SYS_setregid  127
%define SYS_rename    128
                                ; 129 is obsolete otruncate */
                                ; 130 is obsolete ftruncate */
%define SYS_flock     131
%define SYS_mkfifo    132
%define SYS_sendto    133
%define SYS_shutdown  134
%define SYS_socketpair        135
%define SYS_mkdir     136
%define SYS_rmdir     137
%define SYS_freebsd32_utimes  138
                                ; 139 is obsolete 4.2 sigreturn */
%define SYS_freebsd32_adjtime 140
                                ; 141 is obsolete ogetpeername */
                                ; 142 is obsolete ogethostid */
                                ; 143 is obsolete sethostid */
                                ; 144 is obsolete getrlimit */
                                ; 145 is obsolete setrlimit */
                                ; 146 is obsolete killpg */
%define SYS_setsid    147
%define SYS_quotactl  148
                                ; 149 is obsolete oquota */
                                ; 150 is obsolete ogetsockname */
                                ; 156 is obsolete ogetdirentries */
%define SYS_freebsd32_statfs  157
%define SYS_freebsd32_fstatfs 158
%define SYS_getfh     161
%define SYS_getdomainname     162
%define SYS_setdomainname     163
%define SYS_uname     164
%define SYS_sysarch   165
%define SYS_rtprio    166
%define SYS_freebsd32_semsys  169
%define SYS_freebsd32_msgsys  170
%define SYS_freebsd32_shmsys  171
%define SYS_freebsd32_pread   173
%define SYS_freebsd32_pwrite  174
%define SYS_ntp_adjtime       176
%define SYS_setgid    181
%define SYS_setegid   182
%define SYS_seteuid   183
%define SYS_freebsd32_stat    188
%define SYS_freebsd32_fstat   189
%define SYS_freebsd32_lstat   190
%define SYS_pathconf  191
%define SYS_fpathconf 192
%define SYS_getrlimit 194
%define SYS_setrlimit 195
%define SYS_getdirentries     196
%define SYS_freebsd32_mmap    197
%define SYS___syscall 198
%define SYS_freebsd32_lseek   199
%define SYS_freebsd32_truncate        200
%define SYS_freebsd32_ftruncate       201
%define SYS_freebsd32_sysctl  202
%define SYS_mlock     203
%define SYS_munlock   204
%define SYS_undelete  205
%define SYS_futimes   206
%define SYS_getpgid   207
%define SYS_poll      209
%define SYS___semctl  220
%define SYS_semget    221
%define SYS_semop     222
%define SYS_msgctl    224
%define SYS_msgget    225
%define SYS_msgsnd    226
%define SYS_msgrcv    227
%define SYS_shmat     228
%define SYS_shmctl    229
%define SYS_shmdt     230
%define SYS_shmget    231
%define SYS_clock_gettime     232
%define SYS_clock_settime     233
%define SYS_clock_getres      234
%define SYS_nanosleep 240
%define SYS_minherit  250
%define SYS_rfork     251
%define SYS_openbsd_poll      252
%define SYS_issetugid 253
%define SYS_lchown    254
%define SYS_getdents  272
%define SYS_lchmod    274
%define SYS_netbsd_lchown     275
%define SYS_lutimes   276
%define SYS_netbsd_msync      277
%define SYS_nstat     278
%define SYS_nfstat    279
%define SYS_nlstat    280
%define SYS_fhstatfs  297
%define SYS_fhopen    298
%define SYS_fhstat    299
%define SYS_modnext   300
%define SYS_modstat   301
%define SYS_modfnext  302
%define SYS_modfind   303
%define SYS_kldload   304
%define SYS_kldunload 305
%define SYS_kldfind   306
%define SYS_kldnext   307
%define SYS_kldstat   308
%define SYS_kldfirstmod       309
%define SYS_getsid    310
%define SYS_setresuid 311
%define SYS_setresgid 312
                                ; 313 is obsolete signanosleep */
%define SYS_yield     321
                                ; 322 is obsolete thr_sleep */
                                ; 323 is obsolete thr_wakeup */
%define SYS_mlockall  324
%define SYS_munlockall        325
%define SYS___getcwd  326
%define SYS_sched_setparam    327
%define SYS_sched_getparam    328
%define SYS_sched_setscheduler        329
%define SYS_sched_getscheduler        330
%define SYS_sched_yield       331
%define SYS_sched_get_priority_max    332
%define SYS_sched_get_priority_min    333
%define SYS_sched_rr_get_interval     334
%define SYS_utrace    335
                                ; 336 is old freebsd32_sendfile */
%define SYS_kldsym    337
%define SYS_jail      338
%define SYS_sigprocmask       340
%define SYS_sigsuspend        341
                                ; 342 is old freebsd32_sigaction */
%define SYS_sigpending        343
                                ; 344 is old freebsd32_sigreturn */
%define SYS___acl_get_file    347
%define SYS___acl_set_file    348
%define SYS___acl_get_fd      349
%define SYS___acl_set_fd      350
%define SYS___acl_delete_file 351
%define SYS___acl_delete_fd   352
%define SYS___acl_aclcheck_file       353
%define SYS___acl_aclcheck_fd 354
%define SYS_extattrctl        355
%define SYS_extattr_set_file  356
%define SYS_extattr_get_file  357
%define SYS_extattr_delete_file       358
%define SYS_getresuid 360
%define SYS_getresgid 361
%define SYS_kqueue    362
%define SYS_freebsd32_kevent  363
%define SYS_extattr_set_fd    371
%define SYS_extattr_get_fd    372
%define SYS_extattr_delete_fd 373
%define SYS___setugid 374
%define SYS_eaccess   376
%define SYS_nmount    378
%define SYS_kse_exit  379
%define SYS_kse_wakeup        380
%define SYS_kse_create        381
%define SYS_kse_thr_interrupt 382
%define SYS_kse_release       383
%define SYS_kenv      390
%define SYS_lchflags  391
%define SYS_uuidgen   392
%define SYS_freebsd32_sendfile        393
%define SYS_freebsd32_sigaction       416
%define SYS_freebsd32_sigreturn       417
%define SYS_thr_create        430
%define SYS_thr_exit  431
%define SYS_thr_self  432
%define SYS_thr_kill  433
%define SYS__umtx_lock        434
%define SYS__umtx_unlock      435
%define SYS_jail_attach       436
%define SYS_MAXSYSCALL        441
