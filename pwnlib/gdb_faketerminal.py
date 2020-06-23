#!/usr/bin/env python
from pwnlib.tubes.process import process
from time import sleep
from sys import argv
sleep(1)

# Launch GDB under bash, force an exit after detach
#
# We can't call "detach" because that will put "Detaching from process"
# on stderr of the process, which messes with tests.
#
# Sleep for 3 seconds so that the debugger doesn't exit SO FAST that
# Pwntools doens't have a chance to detect it.
#
# We call sys.exit() directly so there is no extra GDB output.
sh = process(argv[1] + " -ex 'py import os,time; time.sleep(3); sys.exit()'" , shell=True)
sh.close()