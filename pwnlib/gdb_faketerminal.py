#!/usr/bin/env python
from pwnlib.tubes.process import process
from time import sleep
from sys import argv
sleep(1)
sh = process(argv[1], shell=True)
res = sh.sendlineafter('(gdb)', 'c')
while b'The program is not being run.' not in res:
    res = sh.sendlineafter('(gdb)', 'c')
sh.close()
