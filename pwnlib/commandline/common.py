import argparse
import os
import sys

import pwnlib
from pwnlib.context import context

choices = map(str, [16,32,64])
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

def main(file=sys.argv[0]):
    import pwnlib.commandline.main
    name = os.path.splitext(os.path.basename(file))[0]
    sys.argv.insert(1, name)
    pwnlib.commandline.main.main()
