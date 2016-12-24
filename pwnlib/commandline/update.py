#!/usr/bin/env python2
import subprocess

from pwn import *

from . import common

p = common.parser_commands.add_parser(
    'update',
    help = 'Check for pwntools updates'
)

p.add_argument('--install', action='store_true', help='''
    Install the update automatically.
''')

p.add_argument('--pre', action='store_true', help='''
    Check for pre-releases.
''')

def main(a):
    result = pwnlib.update.perform_check(prerelease=a.pre)
    if a.install:
        subprocess.check_call(result, shell=False)

if __name__ == '__main__':
    pwnlib.common.main(__file__)
