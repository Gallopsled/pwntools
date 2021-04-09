#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

import sys

import pwnlib
pwnlib.args.free_form = False

from pwn import *
from pwnlib.commandline import common

p = common.parser_commands.add_parser(
    'elfpatch',
    help = 'Patch an ELF file',
    description = 'Patch an ELF file'
)

p.add_argument('elf',help="File to patch")
p.add_argument('offset',help="Offset to patch in virtual address (hex encoded)")
p.add_argument('bytes',help='Bytes to patch (hex encoded)')


def main(a):
    if not a.offset.startswith('0x'):
        a.offset = '0x' + a.offset

    offset = int(a.offset, 16)
    bytes  = unhex(a.bytes)

    with context.silent:
        elf    = ELF(a.elf)

    elf.write(offset, bytes)
    getattr(sys.stdout, 'buffer', sys.stdout).write(elf.get_data())

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
