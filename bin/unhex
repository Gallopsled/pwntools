#!/usr/bin/env python2
import sys
from string import whitespace
try:
    if len(sys.argv) == 1:
        s = sys.stdin.read().translate(None, whitespace)
        sys.stdout.write(s.decode('hex'))
    else:
        sys.stdout.write(''.join(sys.argv[1:]).decode('hex'))
except TypeError, e:
    sys.stderr.write(str(e) + '\n')
