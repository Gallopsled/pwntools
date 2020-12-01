#!/usr/bin/env python
from __future__ import print_function

import re
import sys

from pwnlib.util import safeeval

python = open(sys.argv[1], "w")
header = open(sys.argv[2], "w")

print('from pwnlib.constants.constant import Constant', file=python)

data = sys.stdin.read().strip().split('\n')

res = ""
regex = re.compile('^%constant ([^=]+) = ([^";]+);')
for l in data:
    m = regex.match(l)
    if not m:
        continue
    if '"' in l or '=' not in l or ';' not in l or not l.startswith('%constant '):
        continue

    key = m.group(1)
    val = m.group(2)

    # Handle weird special cases from C syntax
    paren = False
    if val[:1] == '(' and val[-1:] == ')' and ')' not in val[1:-1]:
        val = val[1:-1]
        paren = True
    val = val.rstrip('UuLl')
    val = val.replace('7ll', '7')

    if re.match(r'^0[0-9]', val):
        val = '0o'+val[1:]
    val = re.sub(r'([|^&( ]0)([0-7])', r'\1o\2', val)

    if paren:
        val = '(%s)' % val
    print("{key} = Constant({key!r},{val})".format(**locals()), file=python)
    if re.search(r'0o[0-7]', val) or re.match(r'[^0-9a-fA-Fx]0[0-9]', val):
        print("#define %s %s" % (key, hex(safeeval.expr(val))), file=header)
    else:
        print("#define %s %s" % (key, val), file=header)
