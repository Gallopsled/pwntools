from __future__ import absolute_import
from __future__ import division

import argparse
import sys

import pwnlib
pwnlib.args.free_form = False

from pwn import *
from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'scramble',
    help = 'Shellcode encoder'
)

parser.add_argument(
    "-f", "--format",
    help="Output format (defaults to hex for ttys, otherwise raw)",
    choices=['raw', 'hex', 'string', 'elf']
)

parser.add_argument(
    "-o","--output",
    metavar='file',
    help="Output file (defaults to stdout)",
    type=argparse.FileType('wb'),
    default=getattr(sys.stdout, 'buffer', sys.stdout)
)

parser.add_argument(
    '-c', '--context',
    metavar = 'context',
    action = 'append',
    type   = common.context_arg,
    choices = common.choices,
    help = 'The os/architecture/endianness/bits the shellcode will run in (default: linux/i386), choose from: %s' % common.choices,
)

parser.add_argument(
    '-p', '--alphanumeric',
    action='store_true',
    help = 'Encode the shellcode with an alphanumeric encoder'
)

parser.add_argument(
    '-v', '--avoid',
    action='append',
    help = 'Encode the shellcode to avoid the listed bytes'
)

parser.add_argument(
    '-n', '--newline',
    dest='avoid',
    action='append_const',
    const='\n',
    help = 'Encode the shellcode to avoid newlines'
)

parser.add_argument(
    '-z', '--zero',
    dest='avoid',
    action='append_const',
    const='\x00',
    help = 'Encode the shellcode to avoid NULL bytes'
)

parser.add_argument(
    '-d',
    '--debug',
    help='Debug the shellcode with GDB',
    action='store_true'
)

def main(args):
    tty    = args.output.isatty()

    if sys.stdin.isatty():
        parser.print_usage()
        sys.exit(0)

    data   = sys.stdin.read()
    output = data
    fmt    = args.format or ('hex' if tty else 'raw')
    formatters = {'r':bytes, 'h':enhex, 's':repr}

    if args.alphanumeric:
        output = alphanumeric(output)

    if args.avoid:
        output = avoid(output, ''.join(args.avoid))

    if args.debug:
        proc = gdb.debug_shellcode(output, arch=context.arch)
        proc.interactive()
        sys.exit(0)

    if fmt[0] == 'e':
        sys.stdout.write(make_elf(output))
    else:
        output = formatters[fmt[0]](output)
        if not hasattr(output, 'decode'):
            output = output.encode('ascii')
        args.output.write(output)

    if tty and fmt is not 'raw':
        args.output.write(b'\n')


if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
