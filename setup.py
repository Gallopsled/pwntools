#!/usr/bin/env python

import glob
import os
import sys
from distutils.command.install import INSTALL_SCHEMES
from distutils.sysconfig import get_python_inc
from distutils.util import convert_path

from setuptools import setup

# Get all template files
templates = []
for dirpath, dirnames, filenames in os.walk(convert_path('pwnlib/shellcraft/templates'), followlinks=True):
    for f in filenames:
        templates.append(os.path.relpath(os.path.join(dirpath, f), 'pwnlib'))

# This makes pwntools-LICENSE.txt appear with the package folders
for scheme in INSTALL_SCHEMES.values():
    scheme['data'] = scheme['purelib']

console_scripts = ['pwn=pwnlib.commandline.main:main']

DEPRECATED_SCRIPTS= [
    'asm',
    # 'checksec',
    # 'constgrep',
    'cyclic',
    'debug',
    'disablenx',
    'disasm',
    'elfdiff',
    'elfpatch',
    'errno',
    'hex',
    # 'libcdb',
    # 'phd',
    # 'pwnstrip',
    'scramble',
    # 'shellcraft',
    'template',
    'unhex',
]

for filename in glob.glob('pwnlib/commandline/*'):
    filename = os.path.basename(filename)
    filename, ext = os.path.splitext(filename)

    if ext != '.py' or filename in ('__init__', 'common', 'main', 'update', 'version'):
        continue

    if filename in DEPRECATED_SCRIPTS:
        script = '%s=pwnlib.commandline.common:deprecated_main' % filename
    else:
        script = '%s=pwnlib.commandline.common:main' % filename
    console_scripts.append(script)

# Check that the user has installed the Python development headers
PythonH = os.path.join(get_python_inc(), 'Python.h')
if not os.path.exists(PythonH):
    print("You must install the Python development headers!", file=sys.stderr)
    print("$ sudo apt-get install python-dev", file=sys.stderr)
    sys.exit(-1)

setup(
    version              = '5.0.0dev',
    data_files           = [('pwntools-doc',
                             glob.glob('*.md') + glob.glob('*.txt')),
                            ],
    package_data         = {
        'pwnlib': [
            'data/crcsums.txt',
            'data/useragents/useragents.txt',
            'data/binutils/*',
            'data/includes/*.h',
            'data/includes/*/*.h',
            'data/templates/*.mako',
        ] + templates,
    },
    entry_points = {'console_scripts': console_scripts},
)
