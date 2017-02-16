#!/usr/bin/env python2
from __future__ import absolute_import

import argparse
import sys

from pwn import *
from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'checksec',
    help = 'Check binary security settings'
)
parser.add_argument(
    'elf',
    nargs='*',
    type=file,
    help='Files to check'
)
parser.add_argument(
    '--file',
    nargs='*',
    dest='elf2',
    metavar='elf',
    type=file,
    help='File to check (for compatibility with checksec.sh)'
)

def main(args):
    files  = args.elf or args.elf2 or []

    if not files:
        parser.print_usage()
        return

    for f in files:
        e = ELF(f.name)

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
