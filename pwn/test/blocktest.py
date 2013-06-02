from pwn import *
from pwn.blocks import *

b = Block([1,2,3])
foo = (42, b << name('foo'), sizeof('foo')) << name('bar')
print repr(flat(foo))
print len(flat(foo))
print len(foo)
