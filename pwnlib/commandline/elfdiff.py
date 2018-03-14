#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

import shutil
from argparse import ArgumentParser
from subprocess import CalledProcessError
from subprocess import check_output
from tempfile import NamedTemporaryFile

import pwnlib
pwnlib.args.free_form = False

from pwn import *
from pwnlib.commandline import common


def dump(objdump, path):
    n = NamedTemporaryFile(delete=False)
    o = check_output([objdump,'-d','-x','-s',path])
    n.write(o)
    n.flush()
    return n.name

def diff(a,b):
    try: return check_output(['diff',a,b])
    except CalledProcessError as e:
        return e.output

p = common.parser_commands.add_parser(
    'elfdiff',
    help = 'Compare two ELF files'
)

p.add_argument('a')
p.add_argument('b')

def main(a):
    with context.silent:
        x = ELF(a.a)
        y = ELF(a.b)

    if x.arch != y.arch:
        log.error("Architectures are not the same: %s vs %s" % (x.arch, y.arch))

    context.arch = x.arch

    objdump = pwnlib.asm.which_binutils('objdump')

    tmp = NamedTemporaryFile()
    name = tmp.name

    shutil.copy(x.path, name)
    x = dump(objdump, name)

    shutil.copy(y.path, name)
    y = dump(objdump, name)

    print(diff(x, y))

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
