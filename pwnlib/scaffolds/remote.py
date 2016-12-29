#!/usr/bin/env python

class RemoteExploitTemplate():
    name = 'remote'
    summary = 'New remote exploit'


    def build(self):
        base = """
#!/usr/bin/env python
from pwn import *

sock = remote('127.0.0.1', 9001)

print(sock.recvline())
sock.send('foo')

sock.interactive()"""

        return base
