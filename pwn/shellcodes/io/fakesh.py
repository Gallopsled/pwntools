from pwn.shellcode_helper import *

@shellcode_reqs(arch='i386', os='linux')
def fakesh():
    return """
        ;; Clear eax, ebx, edx
        xor ebx, ebx
        imul ebx
    
        ;; Push 'sh-4.1$ '
        push `.1$ `
        push `sh-4`
    start:
        ;; Print string
        mov al, 0x4
        mov ecx, esp
        mov dl, 0x8
        int 0x80
    loop:
        ;; Read input
        mov al, 0x3
        lea ecx, [esp+0x8]
        int 0x80
        
        ;; jmp start if newline recieved
        cmp eax, 8
        jb start
        mov ecx, [esp + 0xf]
        cmp cl, 0xa
        je start

        ;; Otherwise read again
        jmp loop
"""
