from pwn.internal.shellcode_helper import *
from ..misc.pushstr import pushstr
from write_stack import write_stack

@shellcode_reqs(arch=['i386', 'amd64'], os=['linux', 'freebsd'])
def echo(str, out = 1):
    """Args: str, [out = 1]
    Writes <str> to <out> (default: STDOUT_FILENO)."""
    return pushstr(str, null=False), write_stack(out, len(str))
