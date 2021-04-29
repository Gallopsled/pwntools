#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

import argparse
import six
import string
import sys

import pwnlib.args
pwnlib.args.free_form = False

from pwn import *
from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'cyclic',
    help = "Cyclic pattern creator/finder",
    description = "Cyclic pattern creator/finder"
)

parser.add_argument(
    '-a', '--alphabet',
    metavar = 'alphabet',
    default = string.ascii_lowercase.encode(),
    type = packing._encode,
    help = 'The alphabet to use in the cyclic pattern (defaults to all lower case letters)',
)

parser.add_argument(
    '-n', '--length',
    metavar = 'length',
    default = 4,
    type = int,
    help = 'Size of the unique subsequences (defaults to 4).'
)

parser.add_argument(
    '-c', '--context',
    metavar = 'context',
    action = 'append',
    type   = common.context_arg,
    choices = common.choices,
    help = 'The os/architecture/endianness/bits the shellcode will run in (default: linux/i386), choose from: %s' % common.choices,
)

group = parser.add_mutually_exclusive_group(required=False)
group.add_argument(
    '-l', '-o', '--offset', '--lookup',
    dest = 'lookup',
    metavar = 'lookup_value',
    help = 'Do a lookup instead printing the alphabet',
)

group.add_argument(
    'count',
    type=int,
    nargs='?',
    default=None,
    help='Number of characters to print'
)

def main(args):
    alphabet = args.alphabet
    subsize  = args.length

    if args.lookup:
        pat = args.lookup

        try:
            pat = int(pat, 0)
        except ValueError:
            pass
        pat = flat(pat, bytes=args.length)

        if len(pat) != subsize:
            log.critical('Subpattern must be %d bytes' % subsize)
            sys.exit(1)

        if not all(c in alphabet for c in pat):
            log.critical('Pattern contains characters not present in the alphabet')
            sys.exit(1)

        offset = cyclic_find(pat, alphabet, subsize)

        if offset == -1:
            log.critical('Given pattern does not exist in cyclic pattern')
            sys.exit(1)
        else:
            print(offset)
    else:
        want   = args.count
        result = cyclic(want, alphabet, subsize)
        got    = len(result)
        if want is not None and got < want:
            log.failure("Alphabet too small (max length = %i)" % got)

        out = getattr(sys.stdout, 'buffer', sys.stdout)
        out.write(result)

        if out.isatty():
            out.write(b'\n')

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
