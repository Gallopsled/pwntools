import argparse
import os
import sys

import pwnlib
from pwnlib.context import context

choices = list(map(str, [16,32,64]))
choices += list(context.oses)
choices += list(context.architectures)
choices += list(context.endiannesses)

def context_arg(arg):
    try: context.arch = arg
    except Exception: pass
    try: context.os = arg
    except Exception: pass
    try: context.bits = int(arg)
    except Exception: arg
    try: context.endian = arg
    except Exception: pass
    return arg

parser = argparse.ArgumentParser(description='Pwntools Command-line Interface',
                                 prog='pwn')
parser_commands = parser.add_subparsers(dest='command')

def main(file=sys.argv[0], command_main=None):
    name = os.path.splitext(os.path.basename(file))[0]
    if command_main is None:
        import importlib
        command_main = importlib.import_module('pwnlib.commandline.%s' % name).main
    sys.argv.insert(1, name)
    entrypoint({name: command_main})

def entrypoint(commands):
    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit()
    args = parser.parse_args()
    with context.local(log_console = sys.stderr):
        commands[args.command](args)
