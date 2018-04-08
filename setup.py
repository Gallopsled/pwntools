#!/usr/bin/env python2
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

from setuptools import find_packages
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

install_requires     = ['paramiko>=1.15.2',
                        'mako>=1.0.0',
                        'pyelftools>=0.2.4',
                        'capstone>=3.0.5rc2', # See Gallopsled/pwntools#971, Gallopsled/pwntools#1160
                        'ropgadget>=5.3',
                        'pyserial>=2.7',
                        'requests>=2.0',
                        'pip>=6.0.8',
                        'tox>=1.8.1',
                        'pygments>=2.0',
                        'pysocks',
                        'python-dateutil',
                        'packaging',
                        'psutil>=3.3.0',
                        'intervaltree',
                        'sortedcontainers<2.0', # See Gallopsled/pwntools#1154
                        'unicorn']

# Check that the user has installed the Python development headers
PythonH = os.path.join(get_python_inc(), 'Python.h')
if not os.path.exists(PythonH):
    print("You must install the Python development headers!", file=sys.stderr)
    print("$ apt-get install python-dev", file=sys.stderr)
    sys.exit(-1)

# Convert README.md to reStructuredText for PyPI
long_description = ''
try:
    long_description = subprocess.check_output(['pandoc', 'README.md', '--to=rst'])
except Exception as e:
    print("Failed to convert README.md through pandoc, proceeding anyway", file=sys.stderr)
    traceback.print_exc()

setup(
    name                 = 'pwntools',
    python_requires      = '>=2.7',
    packages             = find_packages(),
    version              = '3.14.0dev',
    data_files           = [('',
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
    description          = "Pwntools CTF framework and exploit development library.",
    long_description     = long_description,
    author               = "Gallopsled et al.",
    author_email         = "pwntools-users@googlegroups.com",
    url                  = 'https://pwntools.com',
    download_url         = "https://github.com/Gallopsled/pwntools/releases",
    install_requires     = install_requires,
    license              = "Mostly MIT, some GPL/BSD, see LICENSE-pwntools.txt",
    keywords             = 'pwntools exploit ctf capture the flag binary wargame overflow stack heap defcon',
    classifiers          = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
        'Topic :: Software Development :: Assemblers',
        'Topic :: Software Development :: Debuggers',
        'Topic :: Software Development :: Disassemblers',
        'Topic :: Software Development :: Embedded Systems',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: System Shells',
        'Topic :: Utilities',
    ]
)
