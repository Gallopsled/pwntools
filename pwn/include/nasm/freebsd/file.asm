        ;; From /usr/include/sys/unistd.h
        ; whence values for lseek(2)
        %define SEEK_SET        0       ; set file offset to offset
        %define SEEK_CUR        1       ; set file offset to current plus offset
        %define SEEK_END        2       ; set file offset to EOF plus offset
        %define SEEK_DATA       3       ; set file offset to next data past offset
        %define SEEK_HOLE       4       ; set file offset to next hole past offset

        ;; From /usr/include/sys/fcntl.h
        %define O_RDONLY        0x0000          ; open for reading only
        %define O_WRONLY        0x0001          ; open for writing only
        %define O_RDWR          0x0002          ; open for reading and writing
        %define O_ACCMODE       0x0003          ; mask for above modes
        %define FREAD           0x0001
        %define FWRITE          0x0002
        %define O_NONBLOCK      0x0004          ; no delay
        %define O_APPEND        0x0008          ; set append mode
        %define O_SHLOCK        0x0010          ; open with shared file lock
        %define O_EXLOCK        0x0020          ; open with exclusive file lock
        %define O_ASYNC         0x0040          ; signal pgrp when data ready
        %define O_FSYNC         0x0080          ; synchronous writes
        %define O_SYNC          0x0080          ; POSIX synonym for O_FSYNC
        %define O_NOFOLLOW      0x0100          ; don't follow symlinks
        %define O_CREAT         0x0200          ; create if nonexistent
        %define O_TRUNC         0x0400          ; truncate to zero length
        %define O_EXCL          0x0800          ; error if already exists
        %define FHASLOCK        0x4000          ; descriptor holds advisory lock
        ; Defined by POSIX 1003.1; BSD default, but must be distinct from O_RDONLY.
        %define O_NOCTTY        0x8000          ; don't assign controlling terminal
        ; Attempt to bypass buffer cache
        %define O_DIRECT        0x00010000
        ; Defined by POSIX Extended API Set Part 2
        %define O_DIRECTORY     0x00020000      ; Fail if not directory
        %define O_EXEC          0x00040000      ; Open for execute only
        %define FEXEC           O_EXEC
        ; Defined by POSIX 1003.1-2008; BSD default, but reserve for future use.
        %define O_TTY_INIT      0x00080000      ; Restore default termios attributes
        %define O_CLOEXEC       0x00100000
        ; bits to save after open
        %define FMASK   (FREAD|FWRITE|FAPPEND|FASYNC|FFSYNC|FNONBLOCK|O_DIRECT|FEXEC)
        ; bits settable by fcntl(F_SETFL, ...)
        %define FCNTLFLAGS      (FAPPEND|FASYNC|FFSYNC|FNONBLOCK|FRDAHEAD|O_DIRECT)
        %define FPOSIXSHM       O_NOFOLLOW
        %define FCNTLFLAGS      (FAPPEND|FASYNC|FFSYNC|FNONBLOCK|FPOSIXSHM|FRDAHEAD| \
        %define FAPPEND         O_APPEND        ; kernel/compat
        %define FASYNC          O_ASYNC         ; kernel/compat
        %define FFSYNC          O_FSYNC         ; kernel
        %define FNONBLOCK       O_NONBLOCK      ; kernel
        %define FNDELAY         O_NONBLOCK      ; compat
        %define O_NDELAY        O_NONBLOCK      ; compat
        ; Read ahead
        %define FRDAHEAD        O_CREAT
        ; Defined by POSIX Extended API Set Part 2
        %define AT_FDCWD                -100
        %define AT_EACCESS              0x100   ; Check access using effective user and group ID
        %define AT_SYMLINK_NOFOLLOW     0x200   ; Do not follow symbolic links
        %define AT_SYMLINK_FOLLOW       0x400   ; Follow symbolic link
        %define AT_REMOVEDIR            0x800   ; Remove directory instead of file
        ; command values
        %define F_DUPFD         0               ; duplicate file descriptor
        %define F_GETFD         1               ; get file descriptor flags
        %define F_SETFD         2               ; set file descriptor flags
        %define F_GETFL         3               ; get file status flags
        %define F_SETFL         4               ; set file status flags
        %define F_GETOWN        5               ; get SIGIO/SIGURG proc/pgrp
        %define F_SETOWN        6               ; set SIGIO/SIGURG proc/pgrp
        %define F_OGETLK        7               ; get record locking information
        %define F_OSETLK        8               ; set record locking information
        %define F_OSETLKW       9               ; F_SETLK; wait if blocked
        %define F_DUP2FD        10              ; duplicate file descriptor to arg
        %define F_GETLK         11              ; get record locking information
        %define F_SETLK         12              ; set record locking information
        %define F_SETLKW        13              ; F_SETLK; wait if blocked
        %define F_SETLK_REMOTE  14              ; debugging support for remote locks
        %define F_READAHEAD     15              ; read ahead
        %define F_RDAHEAD       16              ; Darwin compatible read ahead
        ; file descriptor flags (F_GETFD, F_SETFD)
        %define FD_CLOEXEC      1               ; close-on-exec flag
        ; record locking flags (F_GETLK, F_SETLK, F_SETLKW)
        %define F_RDLCK         1               ; shared or read lock
        %define F_UNLCK         2               ; unlock
        %define F_WRLCK         3               ; exclusive or write lock
        %define F_UNLCKSYS      4               ; purge locks for a given system ID
        %define F_CANCEL        5               ; cancel an async lock request
        %define F_WAIT          0x010           ; Wait until lock is granted
        %define F_FLOCK         0x020           ; Use flock(2) semantics for lock
        %define F_POSIX         0x040           ; Use POSIX semantics for lock
        %define F_REMOTE        0x080           ; Lock owner is remote NFS client
        %define F_NOINTR        0x100           ; Ignore signals when waiting
        ; lock operations for flock(2)
        %define LOCK_SH         0x01            ; shared file lock
        %define LOCK_EX         0x02            ; exclusive file lock
        %define LOCK_NB         0x04            ; don't block when locking
        %define LOCK_UN         0x08            ; unlock file

        ;; Other
        %define STD_IN          0
        %define STD_OUT         1
        %define STD_ERR         2

