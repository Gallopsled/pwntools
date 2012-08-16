from . import *

def acceptloop(port):
    return \
        "acceptloop:" + \
        listen(port) + \
        """
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
