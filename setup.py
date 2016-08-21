#!/usr/bin/env python2
import glob
import os
import platform
import sys
from distutils.command.install import INSTALL_SCHEMES
from distutils.sysconfig import get_python_inc
from distutils.util import convert_path

from setuptools import find_packages
from setuptools import setup

# Get all template files
templates = []
for dirpath, dirnames, filenames in os.walk(convert_path('pwnlib/shellcraft/templates')):
    for f in filenames:
        templates.append(os.path.relpath(os.path.join(dirpath, f), 'pwnlib'))

# This makes pwntools-LICENSE.txt appear with the package folders
for scheme in INSTALL_SCHEMES.values():
    scheme['data'] = scheme['purelib']

# Find all of the console scripts
console_scripts = []
for filename in glob.glob('pwnlib/commandline/*'):
    filename = os.path.basename(filename)
    filename, ext = os.path.splitext(filename)

    if ext != '.py' or '__init__' in filename:
        continue

    script = '%s=pwnlib.commandline.%s:main' % (filename, filename)
    console_scripts.append(script)

install_requires     = ['paramiko>=1.15.2',
                        'mako>=1.0.0',
                        'pyelftools>=0.2.3',
                        'capstone',
                        'ropgadget>=5.3',
                        'pyserial>=2.7',
                        'requests>=2.0',
                        'pip>=6.0.8',
                        'tox>=1.8.1',
                        'pygments>=2.0',
                        'pysocks',
                        'python-dateutil']

# This is a hack until somebody ports psutil to OpenBSD
if platform.system() != 'OpenBSD':
    install_requires.append('psutil>=2.1.3')

# Check that the user has installed the Python development headers
PythonH = os.path.join(get_python_inc(), 'Python.h')
if not os.path.exists(PythonH):
    print >> sys.stderr, "You must install the Python development headers!"
    print >> sys.stderr, "$ apt-get install python-dev"
    sys.exit(-1)

setup(
    name                 = 'pwntools',
    packages             = find_packages(),
    version              = '3.0.0',
    data_files           = [('',
                             ['LICENSE-pwntools.txt',
                             ]),
                            ],
    package_data         = {
        'pwnlib': [
            'data/crcsums.txt',
            'data/useragents/useragents.txt',
            'data/binutils/*',
            'data/includes/*.h',
            'data/includes/*/*.h',
        ] + templates,
    },
    entry_points = {'console_scripts': console_scripts},
    scripts              = glob.glob("bin/*"),
    description          = "CTF framework and exploit development library.",
    author               = "Zach Riggle",
    author_email         = "zachriggle@gmail.com",
    url                  = 'https://pwntools.com',
    download_url         = "https://pwntools.com/tarball/master",
    install_requires     = install_requires,
    license              = "Mostly MIT, some GPL/BSD, see LICENSE-pwntools.txt and LICENSE-pwntools.txt",
    classifiers          = [
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers'
    ]
)
