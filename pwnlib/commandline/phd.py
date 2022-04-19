#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

import argparse
import os
import signal
import sys
import io

import pwnlib.args
pwnlib.args.free_form = False

from pwn import *
from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'phd',
    help = 'Pretty hex dump',
    description = 'Pretty hex dump'
)

parser.add_argument(
    'file',
    metavar='file',
    nargs='?',
    help='File to hexdump.  Reads from stdin if missing.',
    type=argparse.FileType('rb'),
    default=getattr(sys.stdin, 'buffer', sys.stdin)
)

parser.add_argument(
    "-w", "--width",
    help="Number of bytes per line.",
    default='16',
)

parser.add_argument(
    "-l", "--highlight",
    help="Byte to highlight.",
    nargs="*",
)

parser.add_argument(
    "-s", "--skip",
    help="Skip this many initial bytes.",
    default='0',
)

parser.add_argument(
    "-c", "--count",
    help="Only show this many bytes.",
    default='-1',
)

parser.add_argument(
    "-o", "--offset",
    help="Addresses in left hand column starts at this address.",
    default='0',
)

parser.add_argument(
    "--color",
    nargs='?',
    help="Colorize the output.  When 'auto' output is colorized exactly when stdout is a TTY.  Default is 'auto'.",
    choices = ('always', 'never', 'auto'),
    default='auto',
)

def asint(s):
    if   s.startswith('0x'):
        return int(s, 16)
    elif s.startswith('0'):
        return int(s, 8)
    else:
        return int(s, 10)

def main(args):
    infile = args.file
    width  = asint(args.width)
    skip   = asint(args.skip)
    count  = asint(args.count)
    offset = asint(args.offset)

    # if `--color` has no argument it is `None`
    color = args.color or 'always'
    text.when = color

    if skip:
        try:
            infile.seek(skip, os.SEEK_CUR)
        except IOError:
            infile.read(skip)

    if count != -1:
        infile = io.BytesIO(infile.read(count))

    hl = []
    if args.highlight:
        for hs in args.highlight:
            for h in hs.split(','):
                hl.append(asint(h))

    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    try:
        for line in hexdump_iter(infile, width, highlight = hl, begin = offset + skip):
            print(line)
    except (KeyboardInterrupt, IOError):
        pass

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
