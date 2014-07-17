#!/usr/bin/env python
import sys, string, os


base = sys.argv[1]
opsys   = sys.argv[2]
arch = sys.argv[3]

data = sys.stdin.read().strip().split('\n')

res = ""
for l in data:
    tokens = l.split(' ')
    val = ''.join(tokens[3:]).split(';')[0]

    # Handle weird special cases from C syntax
    if val.endswith('UL'):
        val = val[:-2]
    val = val.replace('""', '"+"')
    res += "{0} = {1}\n".format(tokens[1], val)

with open(os.path.join(base, opsys, arch + '.py'), 'w+') as f:
    f.write(res)
