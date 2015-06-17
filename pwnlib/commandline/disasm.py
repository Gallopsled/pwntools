#!/usr/bin/env python2
import argparse
import string
import sys

from pwn import *

from . import common

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
    metavar = 'arch_or_os',
    action = 'append',
    type   = common.context_arg,
    choices = common.choices,
    help = 'The os/architecture/endianness/bits the shellcode will run in (default: linux/i386), choose from: %s' % common.choices,
)


parser.add_argument(
    "-a","--address",
    metavar='address',
    help="Base address",
    type=str,
    default='0'
)


def main():
    args = parser.parse_args()

    if len(args.hex) > 0:
        dat = ''.join(args.hex)
        dat = dat.translate(None, string.whitespace)
        if not set(string.hexdigits) >= set(dat):
            print "This is not a hex string"
            exit(-1)
        dat = dat.decode('hex')
    else:
        dat = sys.stdin.read()


    if sys.stdout.isatty():
        try:
            from pygments import highlight
            from pygments.formatters import TerminalFormatter
            from pygments.lexers import GasLexer

            offsets = disasm(dat, vma=safeeval.const(args.address), instructions=False, byte=False)
            bytes   = disasm(dat, vma=safeeval.const(args.address), instructions=False, offset=False)
            instrs  = disasm(dat, vma=safeeval.const(args.address), byte=False, offset=False)
            instrs  = highlight(instrs, GasLexer(), TerminalFormatter())

            split = lambda x: x.splitlines()
            for o,b,i in zip(*list(map(split, (offsets, bytes, instrs)))):

                # Highlight NULLs and newlines
                b = b.replace('00', text.red('00'))
                b = b.replace('0a', text.red('0a'))

                print o,b,i
            return
        except ImportError:
            pass

    print disasm(dat, vma=safeeval.const(args.address))

if __name__ == '__main__': main()
