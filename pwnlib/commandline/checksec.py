#!/usr/bin/env python2
import argparse
import sys

from pwn import *

from . import common

parser = argparse.ArgumentParser(
    description = 'Check binary security settings'
)

parser.add_argument(
    'elf',
    nargs='+',
    type=file,
    help='Files to check'
)

def main():
    args   = parser.parse_args()
    for f in args.elf:
        e = ELF(f.name)

if __name__ == '__main__': main()
