from pwn import *

s = ssh('freaken', '82.180.25.186', port = 2223, keyfile = "/home/freaken/.ssh/id_rsa")
c = gdb.ssh_gdb(s, '/bin/sh', 'c')

c.sendline('ls -la')
c.sendline('exit')
print c.recvall()
