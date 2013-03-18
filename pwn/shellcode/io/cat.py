from pwn.internal.shellcode_helper import *
from open_file import open_file
from sendfile import sendfile
from read_stack import read_stack
from write_stack import write_stack

@shellcode_reqs(arch=['i386', 'amd64'], os=['linux', 'freebsd'])
def cat(filepath, out_fd = 1, use_sendfile = False, os = None, arch = None):
    """Args: filepath, [out_fd (imm/reg) = STD_OUT] [use_sendfile]

    Opens a file and writes it to the specified file descriptor.

    Set use_sendfile to True to use the sendfile syscall instead of a read+write loop.
    This causes the shellcode to be slightly smaller.
    """

    if arch == 'i386':
        if os in ['linux', 'freebsd']:
            return _cat_i386(filepath, out_fd, use_sendfile)
    elif arch == 'amd64':
        if os in ['linux', 'freebsd']:
            return _cat_amd64(filepath, out_fd, use_sendfile)

    no_support('cat', os, arch)

def _cat_i386(filepath, out_fd, use_sendfile):
    if use_sendfile:
        return open_file(filepath), sendfile('eax', out_fd)
    else:
        return (open_file(filepath),
               "xchg ebp, eax\ncat_helper1:",
               read_stack('ebp', 48, False),
               "test eax, eax\njle cat_helper2",
               write_stack(out_fd, 'eax'),
               "jmp cat_helper1\ncat_helper2:")

def _cat_amd64(filepath, out_fd, use_sendfile):
    if use_sendfile:
        return open_file(filepath), sendfile('rax', out_fd)
    else:
        return (open_file(filepath),
               "xchg ebp, eax\ncat_helper1:",
               read_stack('rbp', 48, False),
               "test eax, eax\njle cat_helper2",
               write_stack(out_fd, 'rax'),
               "jmp cat_helper1\ncat_helper2:")
