from pwn.internal.shellcode_helper import *

@shellcode_reqs(arch='i386', os='linux')
def write_stack(out_fd = 0, size = 255):
    """Args: [out_fd (imm/reg) = STD_IN] [size(imm/reg) = 255]

    Writes from the stack.

    You can optioanlly shave a few bytes not allocating the stack space.
    """

    size = arg_fixup(size)

    out = """
            setfd ebx, %s""" % out_fd

    if isinstance(size, int):
        out += """
            push SYS_write
            pop eax
            cdq
            mov dl, %s""" % size
    else:
        out += """
            setfd edx, %s
            push SYS_write
            pop eax""" % size

    out += """
            mov ecx, esp
            int 0x80"""

    return out
