#!/usr/bin/env python
from pwnlib.tubes.process import process
from time import sleep
from sys import argv
sleep(1)
sh = process(argv[1], shell=True)
sh.sendlineafter('(gdb)', 'c')
sh.sendlineafter('(gdb)', 'c')
sh.close()
