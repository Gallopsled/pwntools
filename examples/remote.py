"""
Example showing how to use the remote class.
"""

from pwn import *

sock = remote('127.0.0.1', 9001)

print sock.recvline()
sock.send('foo')
sock.interactive()
