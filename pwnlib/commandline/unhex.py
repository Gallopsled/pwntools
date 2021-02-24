#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

import argparse
import sys
from string import whitespace

from pwnlib.commandline import common
from pwnlib.util.fiddling import unhex

parser = common.parser_commands.add_parser(
    'unhex',
    help = 'Decodes hex-encoded data provided on the command line or via stdin.',
    description = 'Decodes hex-encoded data provided on the command line or via stdin.'
)

parser.add_argument('hex', nargs='*',
    help='Hex bytes to decode')

def main(args):
    try:
        o = getattr(sys.stdout, 'buffer', sys.stdout)
        if not args.hex:
            s = getattr(sys.stdin, 'buffer', sys.stdin).read().translate(None, whitespace.encode('ascii'))
            o.write(unhex(s))
        else:
            o.write(unhex(''.join(args.hex)))
    except TypeError as e:
        sys.stderr.write(str(e) + '\n')

if __name__ == '__main__':
    common.main(__file__)
