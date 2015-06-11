#!/usr/bin/env python2
import argparse
import sys

import pwnlib.log
from pwnlib.elf import ELF
from pwnlib.util.fiddling import unhex

pwnlib.log.install_default_handler()

p = argparse.ArgumentParser()
p.add_argument('elf',help="File to patch")
p.add_argument('offset',help="Offset to patch in virtual address (hex encoded)")
p.add_argument('bytes',help='Bytes to patch (hex encoded)')


def main():
    a = p.parse_args()

    if not a.offset.startswith('0x'):
        a.offset = '0x' + a.offset

    offset = int(a.offset, 16)
    bytes  = unhex(a.bytes)
    elf    = ELF(a.elf)

    elf.write(offset, bytes)
    sys.stdout.write(elf.get_data())

if __name__ == '__main__': main()
