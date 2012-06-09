        ;; From /usr/include/bits/mman.h
        %define PROT_READ       0x1 ; Page can be read.
        %define PROT_WRITE      0x2 ; Page can be written.
        %define PROT_EXEC       0x4 ; Page can be executed.
        %define PROT_NONE       0x0 ; Page can not be accessed.
        %define PROT_GROWSDOWN  0x01000000 ; Extend change to start of
                                           ; growsdown vma (mprotect only).
        %define PROT_GROWSUP    0x02000000 ; Extend change to start of
                                           ; growsup vma (mprotect only).
        ;; Sharing types (must choose one and only one of these).
        %define MAP_SHARED      0x01 ; Share changes.
        %define MAP_PRIVATE     0x02 ; Changes are private.
        %define MAP_TYPE        0x0f ; Mask for type of mapping.

        ;; Other flags.
        %define MAP_FIXED       0x10 ; Interpret addr exactly.
        %define MAP_FILE        0
        %define MAP_ANONYMOUS   0x20 ; Don't use a file.
        %define MAP_ANON        MAP_ANONYMOUS
        %define MAP_32BIT       0x40 ; Only give out 32-bit addresses.

        ;; These are Linux-specific.
        %define MAP_GROWSDOWN   0x00100 ; Stack-like segment.
        %define MAP_DENYWRITE   0x00800 ; ETXTBS
        %define MAP_EXECUTABLE  0x01000 ; Mark it as an executable.
        %define MAP_LOCKED      0x02000 ; Lock the mapping.
        %define MAP_NORESERVE   0x04000 ; Don't check for reservations.
        %define MAP_POPULATE    0x08000 ; Populate (prefault) pagetables.
        %define MAP_NONBLOCK    0x10000 ; Do not block on IO.
        %define MAP_STACK       0x20000 ; Allocation is for a stack.
        %define MAP_HUGETLB     0x40000 ; Create huge page mapping.
