#!/usr/bin/env python
import os
arg = 'exec ' + argv[1] + ' -ex detach -batch'
args = ['bash', '-c', arg]
sys.stderr.write(repr(args))
os.execve('/bin/bash', args, os.environ)
