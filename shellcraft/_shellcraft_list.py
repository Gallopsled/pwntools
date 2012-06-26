#!/usr/bin/env python

import os, sys
from os.path import join, relpath
import pwn

archs = ['i386', 'amd64', 'mips', 'sparc', 'alpha64', 'powerpc64']

pwnpath = os.path.dirname(pwn.__file__)

def shellcraft_list():
    codez = []
    for arch in archs:
        for dir, _, files in os.walk(join(pwnpath, arch)):
            try:
                files.remove('__init__.py')
            except ValueError:
                pass
            files = filter(lambda x: x.endswith('.py'), files)
            codez += (map(lambda x: relpath(join(dir, x), pwnpath)[:-3].replace('/', '.'), files))
    return sorted(codez)

if __name__ == '__main__':
    for x in shellcraft_list():
        print x
