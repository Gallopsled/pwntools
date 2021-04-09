#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

import argparse
import sys

from pwnlib.commandline import common
from pwnlib.util.fiddling import enhex

parser = common.parser_commands.add_parser(
    'hex',
    help = 'Hex-encodes data provided on the command line or stdin',
    description = 'Hex-encodes data provided on the command line or stdin')

parser.add_argument('data', nargs='*',
    help='Data to convert into hex')

def main(args):
    if not args.data:
        print(enhex(getattr(sys.stdin, 'buffer', sys.stdin).read()))
    else:
        data = ' '.join(args.data)
        if not hasattr(data, 'decode'):
            data = data.encode('utf-8', 'surrogateescape')
        print(enhex(data))

if __name__ == '__main__':
    common.main(__file__)
