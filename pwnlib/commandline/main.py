from __future__ import absolute_import

import sys

from pwnlib.commandline import asm
from pwnlib.commandline import checksec
from pwnlib.commandline import common
from pwnlib.commandline import constgrep
from pwnlib.commandline import cyclic
from pwnlib.commandline import debug
from pwnlib.commandline import disasm
from pwnlib.commandline import disablenx
from pwnlib.commandline import elfdiff
from pwnlib.commandline import elfpatch
from pwnlib.commandline import errno
from pwnlib.commandline import hex
from pwnlib.commandline import phd
from pwnlib.commandline import pwnstrip
from pwnlib.commandline import scramble
from pwnlib.commandline import shellcraft
from pwnlib.commandline import template
from pwnlib.commandline import unhex
from pwnlib.commandline import update
from pwnlib.commandline import version
from pwnlib.commandline.common import parser
from pwnlib.context import context

commands = {
    'asm': asm.main,
    'checksec': checksec.main,
    'constgrep': constgrep.main,
    'cyclic': cyclic.main,
    'debug': debug.main,
    'disasm': disasm.main,
    'disablenx': disablenx.main,
    'elfdiff': elfdiff.main,
    'elfpatch': elfpatch.main,
    'errno': errno.main,
    'hex': hex.main,
    'phd': phd.main,
    'pwnstrip': pwnstrip.main,
    'scramble': scramble.main,
    'shellcraft': shellcraft.main,
    'template': template.main,
    'unhex': unhex.main,
    'update': update.main,
    'version': version.main,
}

def main():
    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit()
    args = parser.parse_args()
    with context.local(log_console = sys.stderr):
        commands[args.command](args)

if __name__ == '__main__':
    main()
