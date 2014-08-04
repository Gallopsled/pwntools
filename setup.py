#!/usr/bin/env python
from setuptools import setup, find_packages
from distutils.util import convert_path
from distutils.command.install import INSTALL_SCHEMES
import os, sys, glob

# Get all template files
templates = []
for dirpath, dirnames, filenames in os.walk(convert_path('pwnlib/shellcraft/templates')):
    for f in filenames:
        templates.append(os.path.relpath(os.path.join(dirpath, f), 'pwnlib'))

# Get the version
ns = {}
with open(convert_path('pwnlib/version.py')) as fd:
    exec fd.read() in ns
version = ns['__version__']

# This makes pwntools-LICENSE.txt appear with the package folders
for scheme in INSTALL_SCHEMES.values():
    scheme['data'] = scheme['purelib']

setup(
    name                 = 'pwntools',
    packages             = find_packages(),
    version              = version,
    data_files           = [('', ['LICENSE-pwntools.txt'])],
    package_data         = {
        'pwnlib': [
            'data/crcsums.txt',
            'data/binutils/*',
            'data/includes/*.h',
            'data/includes/*/*.h',
        ] + templates,
    },
    scripts              = glob.glob("bin/*"),
    description          = "This is the CTF framework used by Gallopsled in every CTF.",
    author               = "Gallopsled et al.",
    author_email         = "#gallopsled @ freenode.net",
    url                  = 'https://github.com/Gallopsled/pwntools/',
    download_url         = "https://github.com/Gallopsled/pwntools/tarball/%s" % version,
    install_requires     = ['paramiko','argparse', 'mako', 'pyelftools', 'capstone', 'ropgadget'],
    license              = "Mostly MIT, some GPL/BSD, see LICENSE-pwntools.txt",
    classifiers          = [
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers'
    ]
)
