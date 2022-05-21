#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

import argparse
import sys

from pwn import *
from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'debug',
    help = 'Debug a binary in GDB',
    description = 'Debug a binary in GDB'
)
parser.add_argument(
    '-x', metavar='GDBSCRIPT',
    type=argparse.FileType('r'),
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
    '--exec',

    # NOTE: Type cannot be "file" because we may be referring to a remote
    #       file, or a file on an Android device.
    type=str,

    dest='executable',
    help='File to debug'
)
parser.add_argument(
    '--process', metavar='PROCESS_NAME',
    help='Name of the process to attach to (e.g. "bash")'
)
parser.add_argument(
    '--sysroot', metavar='SYSROOT',
    type=str,
    default='',
    help="GDB sysroot path"
)

def main(args):
    gdbscript = ''
    if args.x:
        gdbscript = args.x.read()

    if context.os == 'android':
        context.device = adb.wait_for_device()

    if args.executable:
        if os.path.exists(args.executable):
            context.binary = ELF(args.executable)
            target = context.binary.path

        # This path does nothing, but avoids the "print_usage()"
        # path below.
        elif context.os == 'android':
            target = args.executable
    elif args.pid:
        target = int(args.pid)
    elif args.process:
        if context.os == 'android':
            target = adb.pidof(args.process)
        else:
            target = pidof(args.process)

        # pidof() returns a list
        if not target:
            log.error("Could not find a PID for %r", args.process)

        target = target[0]

        # pidof will sometimes return all PIDs, including init
        if target == 1:
            log.error("Got PID 1 from pidof.  Check the process name, or use --pid 1 to debug init")
    else:
        parser.print_usage()
        return 1

    if args.pid or args.process:
        pid = gdb.attach(target, gdbscript=gdbscript, sysroot=args.sysroot)

        # Since we spawned the gdbserver process, and process registers an
        # atexit handler to close itself, gdbserver will be terminated when
        # we exit.  This will manifest as a "remote connected ended" or
        # similar error message.  Hold it open for the user.
        log.info("GDB connection forwarding will terminate when you press enter")
        pause()
    else:
        gdb.debug(target, gdbscript=gdbscript, sysroot=args.sysroot).interactive()

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
