from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'])
def fork(parent, child = None):
    """Fork this shit."""
    code = """
    push byte SYS_fork
    pop eax
    int 0x80
    test eax, eax
    jne %s
""" % parent
    if child is not None:
        code += 'jmp %s\n' % child
    return code
