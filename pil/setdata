#!/usr/bin/env python
import Image, sys

if len(sys.argv) <> 3:
    print "Usage: %s <image> <datafile>" % sys.argv[0]
    sys.exit(1)

im = Image.open(sys.argv[1])
im.load()

with open(sys.argv[2], 'r') as f:
    data = f.read()

im.fromstring(data)
im.save(sys.argv[1])
