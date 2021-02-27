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

description = '''
Pwntools Command-line Interface

Examples:

.. code-block::

    $ pwn asm 'nop'
    90
    $ pwn asm -c arm nop
    00f020e3

    $ pwn disasm 90
    

'''

executable = sys.argv[0]
if os.path.basename(executable) == 'pwn':
    description = description.replace('.. code-block::\n', '')

parser = argparse.ArgumentParser(prog='pwn', 
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=description)

parser_commands = parser.add_subparsers(dest='command')

def main(file=sys.argv[0]):
    import pwnlib.commandline.main
    name = os.path.splitext(os.path.basename(file))[0]
    sys.argv.insert(1, name)
    pwnlib.commandline.main.main()
