#!/usr/bin/env python
import sys, string, os, re

python = open(sys.argv[1], "w")
header = open(sys.argv[2], "w")

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
    if val.endswith('UL'):
        val = val[:-2]
    elif val.endswith('L'):
        val = val[:-1]

    print >> python, "%s = %s" % (key, val)
    print >> header, "#define %s %s" % (key, val)
