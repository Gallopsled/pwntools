#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

import argparse
from pwn import *
from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'disablenx',
    help = 'Disable NX for an ELF binary'
)
parser.add_argument(
    'elf',
    nargs='+',
    type=argparse.FileType('rb'),
    help='Files to check'
)

def main(args):
    for f in args.elf:
        e = ELF(f.name)
        e.disable_nx()
        ELF(e.path)

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
