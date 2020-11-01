#!/usr/bin/env python
from pwnlib.tubes.process import process
from time import sleep
from sys import argv
sleep(1)
if len(argv) == 2:
	sh = process(argv[1], shell=True)
else:
	sh = process(argv[1:])
sh.sendline('set prompt (gdb)')
res = sh.sendlineafter('(gdb)', 'c')
while b'The program is not being run.' not in res:
    res = sh.sendlineafter('(gdb)', 'c')
sh.close()
