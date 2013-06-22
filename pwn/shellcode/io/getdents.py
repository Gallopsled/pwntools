from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os='linux')
def getdents(in_fd = 0, size = 255, allocate_stack = True):
    """Args: [in_fd (imm/reg) = STDIN_FILENO] [size = 255] [allocate_stack = True]

    Reads to the stack from a directory.

    You can optioanlly shave a few bytes not allocating the stack space.

    Leaves the size read in eax.
    """

    out = """
            """ + pwn.shellcode.mov('ebx', in_fd, raw = True) + """
            xor eax, eax
            mov al, SYS_getdents
            cdq
            mov dl, %s""" % size

    if allocate_stack:
        out += """
            sub esp, edx"""

    out += """
            mov ecx, esp
            int 0x80"""

    return out
