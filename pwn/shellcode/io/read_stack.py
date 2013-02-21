from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os='linux')
def read_stack(in_fd = 0, size = 255, allocate_stack = True):
    """Args: [in_fd (imm/reg) = STD_IN] [size = 255] [allocate_stack = True]

    Reads to the stack.

    You can optioanlly shave a few bytes not allocating the stack space.

    Leaves the size read in eax.
    """

    out = """
            setfd ebx, %s
            push SYS_read
            pop eax
            cdq
            mov dl, %s""" % (in_fd, size)

    if allocate_stack:
        out += """
            sub esp, edx"""

    out += """
            mov ecx, esp
            int 0x80"""

    return out
