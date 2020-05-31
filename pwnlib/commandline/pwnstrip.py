from __future__ import absolute_import
from __future__ import division

import argparse

import pwnlib
pwnlib.args.free_form = False

from pwn import *
from pwnlib.commandline import common

p = common.parser_commands.add_parser(
    'pwnstrip',
    help = 'Strip binaries for CTF usage',
)

g = p.add_argument_group("actions")
g.add_argument('-b', '--build-id', help="Strip build ID", action='store_true')
g.add_argument('-p', '--patch', metavar='FUNCTION', help="Patch function", action='append')
p.add_argument('-o', '--output', type=argparse.FileType('wb'), default=getattr(sys.stdout, 'buffer', sys.stdout))
p.add_argument('file', type=argparse.FileType('rb'))

def main(args):
    if not (args.patch or args.build_id):
        sys.stderr.write("Must specify at least one action\n")
        sys.stderr.write(p.format_usage())
        sys.exit(0)

    elf = ELF(args.file.name)
    context.clear(arch=elf.arch)

    if args.build_id:
        for offset in pwnlib.libcdb.get_build_id_offsets():
            data = elf.read(elf.address + offset + 0xC, 4)
            if data == 'GNU\x00':
                elf.write(elf.address + offset + 0x10, os.urandom(20))

    for function in args.patch:
        if function not in elf.symbols:
            log.error("Could not find function %r" % function)

        trap = asm(shellcraft.trap())
        offset = elf.symbols[function]

        elf.write(elf.address + offset, trap)

    result = elf.data

    if args.output.isatty():
        result = enhex(result).encode('ascii')

    args.output.write(result)

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
