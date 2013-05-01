    ;; Syscalls in /usr/include/sys/syscall.h
    %define SYS64_syscall     0
    %define SYS64_exit        1
    %define SYS64_fork        2
    %define SYS64_read        3
    %define SYS64_write       4
    %define SYS64_open        5
    %define SYS64_close       6
    %define SYS64_wait4       7
                                    ; 8 is old creat
    %define SYS64_link        9
    %define SYS64_unlink      10
                                    ; 11 is obsolete execv
    %define SYS64_chdir       12
    %define SYS64_fchdir      13
    %define SYS64_mknod       14
    %define SYS64_chmod       15
    %define SYS64_chown       16
    %define SYS64_break       17
    %define SYS64_freebsd4_getfsstat  18
                                    ; 19 is old lseek
    %define SYS64_getpid      20
    %define SYS64_mount       21
    %define SYS64_unmount     22
    %define SYS64_setuid      23
    %define SYS64_getuid      24
    %define SYS64_geteuid     25
    %define SYS64_ptrace      26
    %define SYS64_recvmsg     27
    %define SYS64_sendmsg     28
    %define SYS64_recvfrom    29
    %define SYS64_accept      30
    %define SYS64_getpeername 31
    %define SYS64_getsockname 32
    %define SYS64_access      33
    %define SYS64_chflags     34
    %define SYS64_fchflags    35
    %define SYS64_sync        36
    %define SYS64_kill        37
                                    ; 38 is old stat
    %define SYS64_getppid     39
                                    ; 40 is old lstat
    %define SYS64_dup 41
    %define SYS64_pipe        42
    %define SYS64_getegid     43
    %define SYS64_profil      44
    %define SYS64_ktrace      45
                                    ; 46 is old sigaction
    %define SYS64_getgid      47
                                    ; 48 is old sigprocmask
    %define SYS64_getlogin    49
    %define SYS64_setlogin    50
    %define SYS64_acct        51
                                    ; 52 is old sigpending
    %define SYS64_sigaltstack 53
    %define SYS64_ioctl       54
    %define SYS64_reboot      55
    %define SYS64_revoke      56
    %define SYS64_symlink     57
    %define SYS64_readlink    58
    %define SYS64_execve      59
    %define SYS64_umask       60
    %define SYS64_chroot      61
                                    ; 62 is old fstat
                                    ; 63 is old getkerninfo
                                    ; 64 is old getpagesize
    %define SYS64_msync       65
    %define SYS64_vfork       66
                                    ; 67 is obsolete vread
                                    ; 68 is obsolete vwrite
    %define SYS64_sbrk        69
    %define SYS64_sstk        70
                                    ; 71 is old mmap
    %define SYS64_vadvise     72
    %define SYS64_munmap      73
    %define SYS64_mprotect    74
    %define SYS64_madvise     75
                                    ; 76 is obsolete vhangup
                                    ; 77 is obsolete vlimit
    %define SYS64_mincore     78
    %define SYS64_getgroups   79
    %define SYS64_setgroups   80
    %define SYS64_getpgrp     81
    %define SYS64_setpgid     82
    %define SYS64_setitimer   83
                                    ; 84 is old wait
    %define SYS64_swapon      85
    %define SYS64_getitimer   86
                                    ; 87 is old gethostname
                                    ; 88 is old sethostname
    %define SYS64_getdtablesize       89
    %define SYS64_dup2        90
    %define SYS64_fcntl       92
    %define SYS64_select      93
    %define SYS64_fsync       95
    %define SYS64_setpriority 96
    %define SYS64_socket      97
    %define SYS64_connect     98
                                    ; 99 is old accept
    %define SYS64_getpriority 100
                                    ; 101 is old send
                                    ; 102 is old recv
                                    ; 103 is old sigreturn
    %define SYS64_bind        104
    %define SYS64_setsockopt  105
    %define SYS64_listen      106
                                    ; 107 is obsolete vtimes
                                    ; 108 is old sigvec
                                    ; 109 is old sigblock
                                    ; 110 is old sigsetmask
                                    ; 111 is old sigsuspend
                                    ; 112 is old sigstack
                                    ; 113 is old recvmsg
                                    ; 114 is old sendmsg
                                    ; 115 is obsolete vtrace
    %define SYS64_gettimeofday        116
    %define SYS64_getrusage   117
    %define SYS64_getsockopt  118
    %define SYS64_readv       120
    %define SYS64_writev      121
    %define SYS64_settimeofday        122
    %define SYS64_fchown      123
    %define SYS64_fchmod      124
                                    ; 125 is old recvfrom
    %define SYS64_setreuid    126
    %define SYS64_setregid    127
    %define SYS64_rename      128
                                    ; 129 is old truncate
                                    ; 130 is old ftruncate
    %define SYS64_flock       131
    %define SYS64_mkfifo      132
    %define SYS64_sendto      133
    %define SYS64_shutdown    134
    %define SYS64_socketpair  135
    %define SYS64_mkdir       136
    %define SYS64_rmdir       137
    %define SYS64_utimes      138
                                    ; 139 is obsolete 4.2 sigreturn
    %define SYS64_adjtime     140
                                    ; 141 is old getpeername
                                    ; 142 is old gethostid
                                    ; 143 is old sethostid
                                    ; 144 is old getrlimit
                                    ; 145 is old setrlimit
                                    ; 146 is old killpg
    %define SYS64_setsid      147
    %define SYS64_quotactl    148
                                    ; 149 is old quota
                                    ; 150 is old getsockname
    %define SYS64_nlm_syscall 154
    %define SYS64_nfssvc      155
                                    ; 156 is old getdirentries
    %define SYS64_freebsd4_statfs     157
    %define SYS64_freebsd4_fstatfs    158
    %define SYS64_lgetfh      160
    %define SYS64_getfh       161
    %define SYS64_freebsd4_getdomainname      162
    %define SYS64_freebsd4_setdomainname      163
    %define SYS64_freebsd4_uname      164
    %define SYS64_sysarch     165
    %define SYS64_rtprio      166
    %define SYS64_semsys      169
    %define SYS64_msgsys      170
    %define SYS64_shmsys      171
    %define SYS64_freebsd6_pread      173
    %define SYS64_freebsd6_pwrite     174
    %define SYS64_setfib      175
    %define SYS64_ntp_adjtime 176
    %define SYS64_setgid      181
    %define SYS64_setegid     182
    %define SYS64_seteuid     183
    %define SYS64_stat        188
    %define SYS64_fstat       189
    %define SYS64_lstat       190
    %define SYS64_pathconf    191
    %define SYS64_fpathconf   192
    %define SYS64_getrlimit   194
    %define SYS64_setrlimit   195
    %define SYS64_getdirentries       196
    %define SYS64_freebsd6_mmap       197
    %define SYS64___syscall   198
    %define SYS64_freebsd6_lseek      199
    %define SYS64_freebsd6_truncate   200
    %define SYS64_freebsd6_ftruncate  201
    %define SYS64___sysctl    202
    %define SYS64_mlock       203
    %define SYS64_munlock     204
    %define SYS64_undelete    205
    %define SYS64_futimes     206
    %define SYS64_getpgid     207
    %define SYS64_poll        209
    %define SYS64_freebsd7___semctl   220
    %define SYS64_semget      221
    %define SYS64_semop       222
    %define SYS64_freebsd7_msgctl     224
    %define SYS64_msgget      225
    %define SYS64_msgsnd      226
    %define SYS64_msgrcv      227
    %define SYS64_shmat       228
    %define SYS64_freebsd7_shmctl     229
    %define SYS64_shmdt       230
    %define SYS64_shmget      231
    %define SYS64_clock_gettime       232
    %define SYS64_clock_settime       233
    %define SYS64_clock_getres        234
    %define SYS64_ktimer_create       235
    %define SYS64_ktimer_delete       236
    %define SYS64_ktimer_settime      237
    %define SYS64_ktimer_gettime      238
    %define SYS64_ktimer_getoverrun   239
    %define SYS64_nanosleep   240
    %define SYS64_ntp_gettime 248
    %define SYS64_minherit    250
    %define SYS64_rfork       251
    %define SYS64_openbsd_poll        252
    %define SYS64_issetugid   253
    %define SYS64_lchown      254
    %define SYS64_aio_read    255
    %define SYS64_aio_write   256
    %define SYS64_lio_listio  257
    %define SYS64_getdents    272
    %define SYS64_lchmod      274
    %define SYS64_netbsd_lchown       275
    %define SYS64_lutimes     276
    %define SYS64_netbsd_msync        277
    %define SYS64_nstat       278
    %define SYS64_nfstat      279
    %define SYS64_nlstat      280
    %define SYS64_preadv      289
    %define SYS64_pwritev     290
    %define SYS64_freebsd4_fhstatfs   297
    %define SYS64_fhopen      298
    %define SYS64_fhstat      299
    %define SYS64_modnext     300
    %define SYS64_modstat     301
    %define SYS64_modfnext    302
    %define SYS64_modfind     303
    %define SYS64_kldload     304
    %define SYS64_kldunload   305
    %define SYS64_kldfind     306
    %define SYS64_kldnext     307
    %define SYS64_kldstat     308
    %define SYS64_kldfirstmod 309
    %define SYS64_getsid      310
    %define SYS64_setresuid   311
    %define SYS64_setresgid   312
                                    ; 313 is obsolete signanosleep
    %define SYS64_aio_return  314
    %define SYS64_aio_suspend 315
    %define SYS64_aio_cancel  316
    %define SYS64_aio_error   317
    %define SYS64_oaio_read   318
    %define SYS64_oaio_write  319
    %define SYS64_olio_listio 320
    %define SYS64_yield       321
                                    ; 322 is obsolete thr_sleep
                                    ; 323 is obsolete thr_wakeup
    %define SYS64_mlockall    324
    %define SYS64_munlockall  325
    %define SYS64___getcwd    326
    %define SYS64_sched_setparam      327
    %define SYS64_sched_getparam      328
    %define SYS64_sched_setscheduler  329
    %define SYS64_sched_getscheduler  330
    %define SYS64_sched_yield 331
    %define SYS64_sched_get_priority_max      332
    %define SYS64_sched_get_priority_min      333
    %define SYS64_sched_rr_get_interval       334
    %define SYS64_utrace      335
    %define SYS64_freebsd4_sendfile   336
    %define SYS64_kldsym      337
    %define SYS64_jail        338
    %define SYS64_nnpfs_syscall       339
    %define SYS64_sigprocmask 340
    %define SYS64_sigsuspend  341
    %define SYS64_freebsd4_sigaction  342
    %define SYS64_sigpending  343
    %define SYS64_freebsd4_sigreturn  344
    %define SYS64_sigtimedwait        345
    %define SYS64_sigwaitinfo 346
    %define SYS64___acl_get_file      347
    %define SYS64___acl_set_file      348
    %define SYS64___acl_get_fd        349
    %define SYS64___acl_set_fd        350
    %define SYS64___acl_delete_file   351
    %define SYS64___acl_delete_fd     352
    %define SYS64___acl_aclcheck_file 353
    %define SYS64___acl_aclcheck_fd   354
    %define SYS64_extattrctl  355
    %define SYS64_extattr_set_file    356
    %define SYS64_extattr_get_file    357
    %define SYS64_extattr_delete_file 358
    %define SYS64_aio_waitcomplete    359
    %define SYS64_getresuid   360
    %define SYS64_getresgid   361
    %define SYS64_kqueue      362
    %define SYS64_kevent      363
    %define SYS64_extattr_set_fd      371
    %define SYS64_extattr_get_fd      372
    %define SYS64_extattr_delete_fd   373
    %define SYS64___setugid   374
    %define SYS64_eaccess     376
    %define SYS64_afs3_syscall        377
    %define SYS64_nmount      378
    %define SYS64___mac_get_proc      384
    %define SYS64___mac_set_proc      385
    %define SYS64___mac_get_fd        386
    %define SYS64___mac_get_file      387
    %define SYS64___mac_set_fd        388
    %define SYS64___mac_set_file      389
    %define SYS64_kenv        390
    %define SYS64_lchflags    391
    %define SYS64_uuidgen     392
    %define SYS64_sendfile    393
    %define SYS64_mac_syscall 394
    %define SYS64_getfsstat   395
    %define SYS64_statfs      396
    %define SYS64_fstatfs     397
    %define SYS64_fhstatfs    398
    %define SYS64_ksem_close  400
    %define SYS64_ksem_post   401
    %define SYS64_ksem_wait   402
    %define SYS64_ksem_trywait        403
    %define SYS64_ksem_init   404
    %define SYS64_ksem_open   405
    %define SYS64_ksem_unlink 406
    %define SYS64_ksem_getvalue       407
    %define SYS64_ksem_destroy        408
    %define SYS64___mac_get_pid       409
    %define SYS64___mac_get_link      410
    %define SYS64___mac_set_link      411
    %define SYS64_extattr_set_link    412
    %define SYS64_extattr_get_link    413
    %define SYS64_extattr_delete_link 414
    %define SYS64___mac_execve        415
    %define SYS64_sigaction   416
    %define SYS64_sigreturn   417
    %define SYS64_getcontext  421
    %define SYS64_setcontext  422
    %define SYS64_swapcontext 423
    %define SYS64_swapoff     424
    %define SYS64___acl_get_link      425
    %define SYS64___acl_set_link      426
    %define SYS64___acl_delete_link   427
    %define SYS64___acl_aclcheck_link 428
    %define SYS64_sigwait     429
    %define SYS64_thr_create  430
    %define SYS64_thr_exit    431
    %define SYS64_thr_self    432
    %define SYS64_thr_kill    433
    %define SYS64__umtx_lock  434
    %define SYS64__umtx_unlock        435
    %define SYS64_jail_attach 436
    %define SYS64_extattr_list_fd     437
    %define SYS64_extattr_list_file   438
    %define SYS64_extattr_list_link   439
    %define SYS64_ksem_timedwait      441
    %define SYS64_thr_suspend 442
    %define SYS64_thr_wake    443
    %define SYS64_kldunloadf  444
    %define SYS64_audit       445
    %define SYS64_auditon     446
    %define SYS64_getauid     447
    %define SYS64_setauid     448
    %define SYS64_getaudit    449
    %define SYS64_setaudit    450
    %define SYS64_getaudit_addr       451
    %define SYS64_setaudit_addr       452
    %define SYS64_auditctl    453
    %define SYS64__umtx_op    454
    %define SYS64_thr_new     455
    %define SYS64_sigqueue    456
    %define SYS64_kmq_open    457
    %define SYS64_kmq_setattr 458
    %define SYS64_kmq_timedreceive    459
    %define SYS64_kmq_timedsend       460
    %define SYS64_kmq_notify  461
    %define SYS64_kmq_unlink  462
    %define SYS64_abort2      463
    %define SYS64_thr_set_name        464
    %define SYS64_aio_fsync   465
    %define SYS64_rtprio_thread       466
    %define SYS64_sctp_peeloff        471
    %define SYS64_sctp_generic_sendmsg        472
    %define SYS64_sctp_generic_sendmsg_iov    473
    %define SYS64_sctp_generic_recvmsg        474
    %define SYS64_pread       475
    %define SYS64_pwrite      476
    %define SYS64_mmap        477
    %define SYS64_lseek       478
    %define SYS64_truncate    479
    %define SYS64_ftruncate   480
    %define SYS64_thr_kill2   481
    %define SYS64_shm_open    482
    %define SYS64_shm_unlink  483
    %define SYS64_cpuset      484
    %define SYS64_cpuset_setid        485
    %define SYS64_cpuset_getid        486
    %define SYS64_cpuset_getaffinity  487
    %define SYS64_cpuset_setaffinity  488
    %define SYS64_faccessat   489
    %define SYS64_fchmodat    490
    %define SYS64_fchownat    491
    %define SYS64_fexecve     492
    %define SYS64_fstatat     493
    %define SYS64_futimesat   494
    %define SYS64_linkat      495
    %define SYS64_mkdirat     496
    %define SYS64_mkfifoat    497
    %define SYS64_mknodat     498
    %define SYS64_openat      499
    %define SYS64_readlinkat  500
    %define SYS64_renameat    501
    %define SYS64_symlinkat   502
    %define SYS64_unlinkat    503
    %define SYS64_posix_openpt        504
    %define SYS64_gssd_syscall        505
    %define SYS64_jail_get    506
    %define SYS64_jail_set    507
    %define SYS64_jail_remove 508
    %define SYS64_closefrom   509
    %define SYS64___semctl    510
    %define SYS64_msgctl      511
    %define SYS64_shmctl      512
    %define SYS64_lpathconf   513
    %define SYS64_pselect     522
    %define SYS64_posix_fallocate     530
    %define SYS64_posix_fadvise       531
    %define SYS64_MAXSYSCALL  532
