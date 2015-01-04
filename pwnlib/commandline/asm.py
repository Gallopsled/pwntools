#!/usr/bin/env python2

import argparse, sys
from pwnlib.asm           import asm
from pwnlib.context       import context
from pwnlib.util.fiddling import enhex

parser = argparse.ArgumentParser(
    description = 'Assemble shellcode into bytes'
)

parser.add_argument(
    'lines',
    metavar='line',
    nargs='*',
    help='Lines to assemble. If none are supplied, use stdin'
)

parser.add_argument(
    "-f", "--format",
    help="Output format (defaults to hex for ttys, otherwise raw)",
    choices=['raw', 'hex', 'string']
)

parser.add_argument(
    "-o","--output",
    metavar='file',
    help="Output file (defaults to stdout)",
    type=argparse.FileType('w'),
    default=sys.stdout
)

parser.add_argument(
    '-c', '--context',
    metavar = '<opt>',
    choices = context.oses + list(context.architectures),
    default = ['i386','linux'],
    action = 'append',
    help = 'The os/architecture the shellcode will run in (default: linux/i386), choose from: %s' % \
      ', '.join(sorted(context.oses + list(context.architectures)))
)

def main():
    args   = parser.parse_args()
    tty    = args.output.isatty()

    for arch in args.context[::-1]:
        if arch in context.architectures: break
    for os in args.context[::-1]:
        if os in context.oses: break

    data   = '\n'.join(args.lines) or sys.stdin.read()
    output = asm(data.replace(';', '\n'), arch = arch, os = os)
    fmt    = args.format or ('hex' if tty else 'raw')
    formatters = {'r':str, 'h':enhex, 's':repr}

    args.output.write(formatters[fmt[0]](output))

    if tty and fmt is not 'raw':
        args.output.write('\n')

if __name__ == '__main__': main()