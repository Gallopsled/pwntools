from pwn.shellcode_helper import *
from listen import listen

@shellcode_reqs(arch='i386', os='linux', network='ipv4')
def acceptloop(port):
    return "acceptloop:", listen(port), """
    xchg eax, ebx
    push byte SYS_fork
    pop eax
    int 0x80
    test eax, eax
    je .exit
    push byte SYS_close
    pop eax
    int 0x80
    jmp acceptloop
.exit:"""
