#!/usr/bin/env python2
import sys

if len(sys.argv) == 1:
    print sys.stdin.read().encode('hex')
else:
    print ' '.join(sys.argv[1:]).encode('hex')
