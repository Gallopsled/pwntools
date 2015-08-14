#!/usr/bin/env python2

from pwn import *
import sys

context(arch = 'mips', os = 'linux', endian = 'big')

def blobs():
    def mov(n):
        return shellcraft.mov('$v0', i) + '\njr $ra\nori $zero, $zero, 0\n.ascii "yoyoyoyoyoyoyoyo"'
    lower = 0
    num = 0x8000
    while lower <= 0xffffffff:
        sc = '\n'.join([mov(i) for i in range(lower, min(lower + num, 0x100000000))])
        blob = asm(sc)
        i = 0
        for b in blob.split('yoyoyoyoyoyoyoyo'):
            if len(b) > 0:
                sc = b[0:-8]
                if '\n' in sc:
                    print '%d generated newlines' % (lower + i)
                    return
                if '\x00' in sc:
                    print '%d generated nul bytes' % (lower + i)
                    return
                yield (b, lower + i)
            i += 1

        lower += num

def doit():
    r = remote('localhost', 8887)
    for blob, i in blobs():
        if i & 0xff == 0:
            sys.stdout.write('\r0x%08x' % i)
            sys.stdout.flush()

        if not r is None:
            r.send(blob)
            try:
                ret = r.read(4)
                ret = unpack(ret, 32)
                if not ret == i:
                    print '0x%08x != 0x%08x' % (i, ret)
                    sys.exit(-1)
            except Exception as e:
                print e
                print 'Something went wrong after sending:'
                print disasm(blob)
                sys.exit(-1)
doit()
