from pwn import *

context(endianness='little', sign='unsigned')

def legit_leak(addr):
    return p32(addr)

mem = MemLeak(legit_leak)
print mem.b(0x08040001) # prints 1
mem.setd(0x08040000, 0xaabbccdd)
print hex(mem.b(0x08040001))   # prints 0xcc
print mem.raw(0x08040000, 20)  # prints stuff
