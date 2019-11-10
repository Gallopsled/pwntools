#!/usr/bin/env python3

from pwn import *


"""
#TODO
t = tube()
t.recv_raw = lambda n: b'Hello, world'
assert(t.recv() == b'Hello, world')

context.decode = 'ascii'

t = tube()
t.recv_raw = lambda n: b'Hello, world'
d = t.recv()
print(d)
assert(d == 'Hello, world')
"""

# Normal case
t = tube()
t.send_raw = lambda d: print(d)
t.send("1")
t.send(b"2")
t.send(str(3))
#t.send(b"4", encode='ascii') # Will throw error

# Force no encoding
t = tube(encode=False)
t.send_raw = lambda d: print(d)
t.send(b"5") # Works
t.send("6", encode='ascii') # Works
t.send("7") # Will throw error

# Force no encoding, context level
context.encode = False
t = tube()
t.send_raw = lambda d: print(d)
t.send(b"8") # Works
t.send("9", encode='ascii') # Works
#t.send("10") # Will throw error

