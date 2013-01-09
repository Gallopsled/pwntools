bits 32
        %define SYS_open     5
        %define SYS_mmap    90
        %define O_RDONLY     0
        %define MAP_PRIVATE  2
        %define PROT_READ    1
        %define PROT_WRITE   2
        %define PROT_EXEC    4

        ;; Save registers
        pusha

        ;; /proc/self/exe
        push `xe\0\0`
        push 'lf/e'
        push 'c/se'
        push '/pro'

        xor ecx, ecx            ; O_RDONLY
        mov ebx, esp            ; pathname
        mov eax, SYS_open
        int 0x80

        push dword #OFFSET#     ; offset
        push eax                ; file descriptor
        push MAP_PRIVATE        ; flags
                                ; prot
        push PROT_READ | PROT_WRITE | PROT_EXEC
        ;; The length is not known before the bootstrapper is assembled, and it
        ;; cannot be assembled before we know the size of the loader.  Therefore
        ;; the length field is strict so it's doesn't change with it's value
                                ; length
        push strict dword #LENGTH#
        push dword 0            ; addr
        mov ebx, esp
        mov eax, SYS_mmap
        int 0x80

        ;; clean up stack
        add esp, 10 * 4
        ;; jump to bootstrapper
        jmp eax