        ;; From /usr/include/sys/mman.h
        %define PROT_NONE       0x00    ; no permissions
        %define PROT_READ       0x01    ; pages can be read
        %define PROT_WRITE      0x02    ; pages can be written
        %define PROT_EXEC       0x04    ; pages can be executed
        %define MAP_SHARED      0x0001          ; share changes
        %define MAP_PRIVATE     0x0002          ; changes are private
        %define MAP_COPY        MAP_PRIVATE     ; Obsolete
        %define MAP_FIXED        0x0010 ; map addr must be exactly as requested
        %define MAP_RENAME       0x0020 ; Sun: rename private pages to file
        %define MAP_NORESERVE    0x0040 ; Sun: don't reserve needed swap area
        %define MAP_RESERVED0080 0x0080 ; previously misimplemented MAP_INHERIT
        %define MAP_RESERVED0100 0x0100 ; previously unimplemented MAP_NOEXTEND
        %define MAP_HASSEMAPHORE 0x0200 ; region may contain semaphores
        %define MAP_STACK        0x0400 ; region grows down, like a stack
        %define MAP_NOSYNC       0x0800 ; page to but do not sync underlying file
        %define MAP_FILE         0x0000 ; map from file (default)
        %define MAP_ANON         0x1000 ; allocated from memory, swap space
        %define MAP_ANONYMOUS    MAP_ANON ; For compatibility.
        %define MAP_NOCORE       0x00020000 ; dont include these pages in a coredump
        %define MAP_PREFAULT_READ 0x00040000 ; prefault mapping for reading
