#!/usr/bin/env python3
from pwn import *

context.randomize = False
context.log_level = 'error'

def go():
    info('========== %s ==========', context.arch)
    with context.silent:
        sc = asm(shellcraft.sh())
        avoid=b'\x00\n\t '
        enc = encode(sc, avoid=avoid, force=1)
    
    assert not (byteset(avoid) & byteset(enc))
    assert enc != sc

    with context.silent:
        io = ELF.from_bytes(enc).process()
        io.sendline(b'whoami')

    try:
        info('%r', io.recvline() == b'pwntools\n')
    except EOFError:
        info('EOFError')

    with context.silent:
        io.close()


context.clear(arch='i386')
go()

context.clear(arch='amd64')
go()

context.clear(arch='arm')
go()

context.clear(arch='mips')
go()