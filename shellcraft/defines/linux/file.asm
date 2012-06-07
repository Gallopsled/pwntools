        ;; From /usr/include/linux/fs.h
        %define SEEK_SET        0  ; seek relative to beginning of file
        %define SEEK_CUR        1  ; seek relative to current file position
        %define SEEK_END        2  ; seek relative to end of file
        %define SEEK_MAX  SEEK_END
        %define MAY_EXEC        1
        %define MAY_WRITE       2
        %define MAY_READ        4
        %define MAY_APPEND      8
        %define MAY_ACCESS      16
        %define MAY_OPEN        32
        %define MAY_CHDIR       64
        ;; From /usr/include/bits/fcntl.h
        %define O_ACCMODE       0003
        %define O_RDONLY        00
        %define O_WRONLY        01
        %define O_RDWR          02
        %define O_CREAT         0100  ; not fcntl
        %define O_EXCL          0200  ; not fcntl
        %define O_NOCTTY        0400  ; not fcntl
        %define O_TRUNC         01000 ; not fcntl
        %define O_APPEND        02000
        %define O_NONBLOCK      04000
        %define O_NDELAY        O_NONBLOCK
        %define O_SYNC          04010000
        %define O_FSYNC         O_SYNC
        %define O_ASYNC         020000
        %define O_DIRECTORY     0200000  ; Must be a directory.
        %define O_NOFOLLOW      0400000  ; Do not follow links.
        %define O_CLOEXEC       02000000 ; Set close_on_exec.
        %define O_DIRECT        040000   ; Direct disk access.
        %define O_NOATIME       01000000 ; Do not set atime.

        ;; For now Linux has synchronisity options for data and read operations.
        ;; We define the symbols here but let them do the same as O_SYNC since
        ;; this is a superset.
        %define O_DSYNC         010000 ; Synchronize data.
        %define O_RSYNC         O_SYNC ; Synchronize read operations.

        %define O_LARGEFILE     0
        %define O_LARGEFILE     0100000

        ;; Values for the second argument to `fcntl'.
        %define F_DUPFD         0 ; Duplicate file descriptor.
        %define F_GETFD         1 ; Get file descriptor flags.
        %define F_SETFD         2 ; Set file descriptor flags.
        %define F_GETFL         3 ; Get file status flags.
        %define F_SETFL         4 ; Set file status flags.

        ;; Other
        %define STD_IN          0
        %define STD_OUT         1
        %define STD_ERR         2
