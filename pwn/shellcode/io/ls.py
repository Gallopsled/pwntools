from pwn.internal.shellcode_helper import *
from open_file import open_file
from write_stack import write_stack
from getdents import getdents

@shellcode_reqs(arch='i386', os='linux')
def ls(filepath = '.', out_fd = 1):
    """Args: filepath, [out_fd (imm/reg) = STDOUT_FILENO]

    Opens a directory and writes its content to the specified file descriptor.
    """

    return (open_file(filepath),
            "xchg ebp, eax\nls_helper1:",
            getdents('ebp', 255, False),
            "test eax, eax\njle ls_helper2",
            write_stack(out_fd, 'eax'),
            "jmp ls_helper1\nls_helper2:")
