        ;; From /usr/include/sys/signal.h
        %define SIGHUP          1       ; hangup
        %define SIGINT          2       ; interrupt
        %define SIGQUIT         3       ; quit
        %define SIGILL          4       ; illegal instr. (not reset when caught)
        %define SIGTRAP         5       ; trace trap (not reset when caught)
        %define SIGABRT         6       ; abort()
        %define SIGIOT          SIGABRT ; compatibility
        %define SIGEMT          7       ; EMT instruction
        %define SIGFPE          8       ; floating point exception
        %define SIGKILL         9       ; kill (cannot be caught or ignored)
        %define SIGBUS          10      ; bus error
        %define SIGSEGV         11      ; segmentation violation
        %define SIGSYS          12      ; non-existent system call invoked
        %define SIGPIPE         13      ; write on a pipe with no one to read it
        %define SIGALRM         14      ; alarm clock
        %define SIGTERM         15      ; software termination signal from kill
        %define SIGURG          16      ; urgent condition on IO channel
        %define SIGSTOP         17      ; sendable stop signal not from tty
        %define SIGTSTP         18      ; stop signal from tty
        %define SIGCONT         19      ; continue a stopped process
        %define SIGCHLD         20      ; to parent on child stop or exit
        %define SIGTTIN         21      ; to readers pgrp upon background tty read
        %define SIGTTOU         22      ; like TTIN if (tp->t_local&LTOSTOP)
        %define SIGIO           23      ; input/output possible signal
        %define SIGXCPU         24      ; exceeded CPU time limit
        %define SIGXFSZ         25      ; exceeded file size limit
        %define SIGVTALRM       26      ; virtual time alarm
        %define SIGPROF         27      ; profiling time alarm
        %define SIGWINCH        28      ; window size changes
        %define SIGINFO         29      ; information request
        %define SIGUSR1         30      ; user defined signal 1
        %define SIGUSR2         31      ; user defined signal 2
        %define SIGTHR          32      ; reserved by thread library.
        %define SIGLWP          SIGTHR
        %define SIGRTMIN        65
        %define SIGRTMAX        126

        %define SIG_DFL         0
        %define SIG_IGN         1
        %define SIG_ERR         -1
        %define SIG_HOLD        3
