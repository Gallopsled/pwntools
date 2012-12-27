# Mario Vilas, http://breakingcode.wordpress.com
# Licensed Under GPLv3

# Example code

import distorm3
import sys
import optparse

# Parse the command line arguments
usage  = 'Usage: %prog [--b16 | --b32 | --b64] filename [offset]'
parser = optparse.OptionParser(usage=usage)
parser.add_option(  '--b16', help='80286 decoding',
                    action='store_const', dest='dt', const=distorm3.Decode16Bits  )
parser.add_option(  '--b32', help='IA-32 decoding [default]',
                    action='store_const', dest='dt', const=distorm3.Decode32Bits  )
parser.add_option(  '--b64', help='AMD64 decoding',
                    action='store_const', dest='dt', const=distorm3.Decode64Bits  )
parser.set_defaults(dt=distorm3.Decode32Bits)
options, args = parser.parse_args(sys.argv)
if len(args) < 2:
    parser.error('missing parameter: filename')
filename = args[1]
offset   = 0
length   = None
if len(args) == 3:
    try:
        offset = int(args[2], 10)
    except ValueError:
        parser.error('invalid offset: %s' % args[2])
    if offset < 0:
        parser.error('invalid offset: %s' % args[2])
elif len(args) > 3:
    parser.error('too many parameters')

# Read the code from the file
try:
    code = open(filename, 'rb').read()
except Exception as e:
    parser.error('error reading file %s: %s' % (filename, e))

# Print each decoded instruction
# This shows how to use the Deocode - Generator
iterable = distorm3.DecodeGenerator(offset, code, options.dt)
for (offset, size, instruction, hexdump) in iterable:
    print("%.8x: %-32s %s" % (offset, hexdump, instruction))

# It could also be used as a returned list:
# l = distorm3.Decode(offset, code, options.dt)
# for (offset, size, instruction, hexdump) in l:
#     print("%.8x: %-32s %s" % (offset, hexdump, instruction))
