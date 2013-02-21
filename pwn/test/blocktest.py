from pwn import *
from pwn.blocks import *

context('i386', 'linux')

b = block()
c = block()
b += 42
b += c.length32, later("foo")
c += b.length64, expr(lambda: wat)
b += shellcode.exit()

wat = 88
b.foo = 17

print b
print c
print len(b)
print len(c)
print flat(b).encode('hex')
print flat(c).encode('hex')
