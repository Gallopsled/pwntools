#!/usr/bin/env python
from __future__ import print_function

import glob
import os
import platform
import subprocess
import sys
import traceback
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

# Find all of the ancillary console scripts
# We have a magic flag --include-all-scripts
flag = '--only-use-pwn-command'
if flag in sys.argv:
    sys.argv.remove(flag)
else:
    flag = False

for filename in glob.glob('pwnlib/commandline/*'):
    filename = os.path.basename(filename)
    filename, ext = os.path.splitext(filename)

    if ext != '.py' or '__init__' in filename:
        continue

    script = '%s=pwnlib.commandline.common:main' % filename
    if not flag:
        console_scripts.append(script)

compat = {}
if sys.version_info < (3, 4):
    import toml
    project = toml.load('pyproject.toml')['project']
    compat['install_requires'] = project['dependencies']
    compat['name'] = project['name']
    if '--user' in sys.argv:
        sys.argv.remove('--user')


# Check that the user has installed the Python development headers
PythonH = os.path.join(get_python_inc(), 'Python.h')
if not os.path.exists(PythonH):
    print("You must install the Python development headers!", file=sys.stderr)
    print("$ apt-get install python-dev", file=sys.stderr)
    sys.exit(-1)

setup(
    version              = '4.11.0',
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
    scripts              = glob.glob("bin/*"),
    **compat
)
