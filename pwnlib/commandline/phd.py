#!/usr/bin/env python2
import argparse
import os
import re
import sys

import pwnlib.log
import pwnlib.term.text as text
from pwnlib.util.fiddling import hexdump_iter

pwnlib.log.install_default_handler()

parser = argparse.ArgumentParser(
    description = 'Pwnlib HexDump'
)

parser.add_argument(
    'file',
    metavar='file',
    nargs='?',
    help='File to hexdump.  Reads from stdin if missing.',
    type=argparse.FileType('r'),
    default=sys.stdin
)

parser.add_argument(
    "-w", "--width",
    help="Number of bytes per line.",
    default='16',
)

parser.add_argument(
    "-l", "--highlight",
    help="Byte sequence to highlight.  Use '?' to match arbitrary bytes and "\
         "'\\?' to match an actual question mark.  Use '\\xXX' for non-"\
         "printable bytes.",
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

def main():
    args = parser.parse_args()

    infile = args.file
    width  = asint(args.width)
    skip   = asint(args.skip)
    count  = asint(args.count)
    offset = asint(args.offset)

    # if `--color` has no argument it is `None`
    color = args.color or 'always'
    text.when = color

    if skip:
        if infile == sys.stdin:
            infile.read(skip)
        else:
            infile.seek(skip, os.SEEK_CUR)

    if args.highlight:
        def canon(hl):
            out = []
            i = 0
            while i < len(hl):
                c = hl[i]
                if c == '\\' and len(hl) > i + 1:
                    c2 = hl[i + 1]
                    if   c2 == 'x':
                        try:
                            b = chr(int(hl[i + 2: i + 4], 16))
                        except:
                            print 'Bad escape sequence:', hl[i:]
                            sys.exit(1)
                        out.append(b)
                        i += 3
                    elif c2 in '\\?':
                        out.append(c2)
                        i += 1
                    else:
                        out.append(c)
                elif c == '?':
                    out.append(None)
                else:
                    out.append(c)
                i += 1
            return out
        highlight = map(canon, args.highlight)
    else:
        highlight = []

    try:
        for line in hexdump_iter(infile, width, highlight = highlight, begin = offset + skip):
            print line
    except (KeyboardInterrupt, IOError):
        pass

if __name__ == '__main__': main()
