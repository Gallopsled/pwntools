#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import string
import sys

import pwnlib
pwnlib.args.free_form = False

from pwn import *
from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'disasm',
    help = 'Disassemble bytes into text format'
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


parser.add_argument(
    '--color',
    help="Color output",
    action='store_true',
    default=sys.stdout.isatty()
)

parser.add_argument(
    '--no-color',
    help="Disable color output",
    action='store_false',
    dest='color'
)


def main(args):
    if len(args.hex) > 0:
        dat = ''.join(args.hex).encode('utf-8', 'surrogateescape')
        dat = dat.translate(None, string.whitespace.encode('ascii'))
        if not set(string.hexdigits.encode('ascii')) >= set(dat):
            print("This is not a hex string")
            exit(-1)
        dat = unhex(dat)
    else:
        dat = getattr(sys.stdin, 'buffer', sys.stdin).read()


    if args.color:
        from pygments import highlight
        from pygments.formatters import TerminalFormatter
        from pwnlib.lexer import PwntoolsLexer

        offsets = disasm(dat, vma=safeeval.const(args.address), instructions=False, byte=False)
        bytes   = disasm(dat, vma=safeeval.const(args.address), instructions=False, offset=False)
        instrs  = disasm(dat, vma=safeeval.const(args.address), byte=False, offset=False)
        # instrs  = highlight(instrs, PwntoolsLexer(), TerminalFormatter())

        for o,b,i in zip(*map(str.splitlines, (offsets, bytes, instrs))):
            b = b.replace('00', text.red('00'))
            b = b.replace('0a', text.red('0a'))
            i = highlight(i.strip(), PwntoolsLexer(), TerminalFormatter()).strip()
            i = i.replace(',',', ')

            print(o,b,i)
        return

    print(disasm(dat, vma=safeeval.const(args.address)))

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
