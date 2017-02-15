#!/usr/bin/env python2
from __future__ import absolute_import

import argparse
import sys

from pwn import *
from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'debug',
    help = 'Debug a binary in GDB'
)
parser.add_argument(
    '-x', metavar='GDBSCRIPT',
    type=file,
    help='Execute GDB commands from this file.'
)
parser.add_argument(
    '--pid',
    type=int,
    help="PID to attach to"
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
    '--exec', type=file, dest='executable',
    help='File to debug'
)
parser.add_argument(
    '--process', metavar='PROCESS_NAME',
    help='Name of the process to attach to (e.g. "bash")'
)

def main(args):
    gdbscript = ''
    if args.x:
        gdbscript = args.x.read()

    if context.os == 'android':
        context.device = adb.wait_for_device()

    if args.executable:
        context.binary = ELF(args.executable.name)
        target = context.binary.path
    elif args.pid:
        target = int(args.pid)
    elif args.process:
        if context.os == 'android':
            target = adb.pidof(process)
        else:
            target = pidof(process)
    else:
        parser.print_usage()
        return 1

    if args.pid or args.process:
        gdb.attach(target, gdbscript=gdbscript)
    else:
        gdb.debug(target, gdbscript=gdbscript).interactive()

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
