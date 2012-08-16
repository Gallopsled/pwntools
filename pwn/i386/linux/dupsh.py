from . import *

def dupsh(sock = 'ebp'):
    """Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr and spawns a shell."""
    return dup(sock) + sh(False)
