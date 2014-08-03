"""
Simple example showing how to use the remote
gdb debugging features available in pwntools.
"""

from pwn import *

s = ssh('user', '127.0.0.1', port = 1234, keyfile = "/home/user/.ssh/id_rsa")
c = gdb.ssh_gdb(s, '/bin/sh', execute = '''
p/x $pc
c''')

c.sendline('ls -la')
c.sendline('exit')
print c.recvall()
