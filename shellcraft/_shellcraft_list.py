#!/usr/bin/env python

import os, sys
from os.path import join
from glob import iglob
from core import *

CODEZ = join(sys.path[0], CODEZ)

def shellcraft_list():
    codez = []
    for dir, _, files in os.walk(CODEZ):
        files.remove('__init__.py')
        files = filter(lambda x: x.endswith('.py'), files)
        codez += (map(lambda x: relpath(join(dir, x), CODEZ)[:-3].replace('/', '.'), files))
    return sorted(codez)

if __name__ == '__main__':
    for x in shellcraft_list():
        print x
