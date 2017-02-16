#!/usr/bin/env python2
from __future__ import absolute_import

import argparse
import sys

from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'hex',
    help = '''
Hex-encodes data provided on the command line or stdin
''')
parser.add_argument('data', nargs='*',
    help='Data to convert into hex')

def main(args):
    if not args.data:
        print sys.stdin.read().encode('hex')
    else:
        print ' '.join(args.data).encode('hex')

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
