#!/usr/bin/env python
import argparse

from pwn import *

from . import common

pwnlib.log.console.stream = sys.stderr

parser = argparse.ArgumentParser()
parser.add_argument('shellcode', nargs='?', default=sys.stdin, type=file)
parser.add_argument(
    '-c', '--context',
    metavar = '<opt>',
    action = 'append',
    type   = common.context_arg,
    choices = common.choices,
    help = 'The os/architecture/endianness/bits the shellcode will run in (default: linux/i386), choose from: %s' % common.choices,
)

def main():
    args = parser.parse_args()

    elf_data = make_elf(args.shellcode.read())
    tmp      = tempfile.mktemp()
    try:
        with open(tmp, 'wb+') as f:
            f.write(elf_data)
            f.flush()
        os.chmod(tmp, 0777)

        proc = gdb.debug(tmp)
        proc.interactive()
        proc.wait_for_close()
    except Exception:
        raise
    else:
        os.unlink(tmp)

if __name__ == '__main__': main()
