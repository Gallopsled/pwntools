#!/usr/bin/env python
import Image, sys

if len(sys.argv) <> 3:
    print "Usage: %s <image> <data>" % sys.argv[0]
    sys.exit(1)

im = Image.open(sys.argv[1])

with open(sys.argv[2], 'w') as f:
    f.write(im.tostring())
