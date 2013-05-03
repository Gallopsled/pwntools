from pwn import *

print 'You chose %d' % options('Pick one:', ['foo', 'bar', 'baz'] * 4)
