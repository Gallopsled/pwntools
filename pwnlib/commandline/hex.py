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

parser.add_argument(
    '-p', '--prefix',
    metavar = 'prefix',
    type = str,
    default = '',
    help = 'Insert a prefix before each byte',
)

parser.add_argument(
    '-s', '--separator',
    metavar = 'separator',
    type = str,
    default = '',
    help = 'Add a separator between each byte',
)

def format_hex(s, prefix, separator):
    n = 2
    parts = [s[i:i+n] for i in range(0, len(s), n)]
    return separator.join([f"{prefix}{x}" for x in parts])

def main(args):
    if not args.data:
        encoded = enhex(getattr(sys.stdin, 'buffer', sys.stdin).read())
    else:
        data = ' '.join(args.data)
        if not hasattr(data, 'decode'):
            data = data.encode('utf-8', 'surrogateescape')
        encoded = enhex(data)

    if args.prefix or args.separator:
        encoded = format_hex(encoded, args.prefix, args.separator)

    print(encoded)

if __name__ == '__main__':
    common.main(__file__)
