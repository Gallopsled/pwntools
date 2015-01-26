#!/usr/bin/env python2
import argparse, sys
from pwn import *
from .   import common

parser = argparse.ArgumentParser(
    description = 'Disassemble bytes into text format'
)

parser.add_argument(
    'hex',
    metavar = 'hex',
    nargs = '*',
    help = 'Hex-string to disasemble. If none are supplied, then it uses stdin in non-hex mode.'
)

parser.add_argument(
    '-c', '--context',
    metavar = '<opt>',
    action = 'append',
    type   = common.context_arg,
    choices = common.choices,
    help = 'The os/architecture/endianness/bits the shellcode will run in (default: linux/i386), choose from: %(choices)s'
)


def main():
    args = parser.parse_args()

    if len(args.hex) > 0:
        dat = ''.join(args.hex)
        dat = dat.translate(None, whitespace)
        if not set(hexdigits) >= set(dat):
            print "This is not a hex string"
            exit(-1)
        dat = dat.decode('hex')
    else:
        dat = sys.stdin.read()

    print asm.disasm(dat)

if __name__ == '__main__': main()
