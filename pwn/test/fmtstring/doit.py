from pwn import *

def fun(x):
    P = process('./a.out', x)
    P.recvline()
    return P

idx = fmt_findoffset(fun)
print idx
