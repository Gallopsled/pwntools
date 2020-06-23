#!/usr/bin/env python
from pwnlib.tubes.process import process
from time import sleep
from sys import argv
sleep(1)

# Launch GDB under bash
sh = process(argv[1], shell=True)

# Sleep for long enough for pwntools to find out that the debugger has attached
sleep(5)

# Detach from the debuggee after the script runs
sh.sendline('detach')
sh.sendline('quit')
sh.recvall()
