from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch=['i386', 'amd64'], os=['linux', 'freebsd'])
def fork(parent, child = None, os = None, arch = None):
    """Fork this shit."""

    if arch == 'i386':
        if os in ['linux', 'freebsd']:
            return _fork_i386(parent, child)
    elif arch == 'amd64':
        if os in ['linux', 'freebsd']:
            return _fork_amd64(parent, child)

    bug('OS/arch combination (%s, %s) was not supported for fork' % (os, arch))

def _fork_amd64(parent, child):
    code = """
    push SYS_fork
    pop rax
    syscall
    test rax, rax
    jne %s
""" % parent
    if child is not None:
        code += 'jmp %s\n' % child
    return code

def _fork_i386(parent, child):
    code = """
    push SYS_fork
    pop eax
    int 0x80
    test eax, eax
    jne %s
""" % parent
    if child is not None:
        code += 'jmp %s\n' % child
    return code
