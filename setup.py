#!/usr/bin/env python
from distutils.core import setup
import os, types, sys


package_description = """
This is the CTF framework used by Gallopsled in every CTF.
""".strip()

scripts = [
    'bin/asm',
    'bin/cyclic',
    'bin/disasm',
    'bin/hex',
    'bin/shellcraft',
    'bin/unhex',
]

def fullsplit(path, result=None):
    """
    Split a pathname into components (the opposite of os.path.join) in a
    platform-neutral way.
    """
    if result is None:
        result = []
    head, tail = os.path.split(path)
    if head == '':
        return [tail] + result
    if head == path:
        return result
    return fullsplit(head, [tail] + result)

# Change into the relevant directory
root_dir = os.path.dirname(__file__)
if root_dir != '':
    os.chdir(root_dir)

sys.path.append(os.getcwd())

# We would like to have the mako templates for shellcode precompiled
def walker(val):
    for k in dir(val):
        if not k or k[0] == '_':
            continue
        nextval = getattr(val, k)
        if isinstance(nextval, types.ModuleType):
            walker(nextval)
import pwnlib.shellcraft
walker(pwnlib.shellcraft)

for dirpath, dirnames, filenames in os.walk(os.path.join('pwnlib', 'shellcraft', 'pycs')):
    open(os.path.join(dirpath, '__init__.py'), 'w')

# Compile the list of packages available, because distutils doesn't have
# an easy way to do this.
packages = []

for package_dir in ['pwn', 'pwnlib']:
    for dirpath, dirnames, filenames in os.walk(package_dir):
        # Ignore dirnames that start with '.'
        for i, dirname in enumerate(dirnames):
            if dirname.startswith('.'): del dirnames[i]
        if '__init__.py' in filenames:
            packages.append('.'.join(fullsplit(dirpath)))

setup(
    name         = 'pwntools',
    packages     = packages,
    version      = '2.0',
    package_data = {
        'pwnlib': [
            'data/crcsums.txt',
            'data/binutils/*',
            'data/includes/*.h',
            'data/includes/*/*.h',
            'shellcraft/templates/*',
            'shellcraft/templates/*/*',
            'shellcraft/templates/*/*/*',
            'shellcraft/templates/*/*/*/*',
            'shellcraft/templates/*/*/*/*/*',
            'shellcraft/templates/*/*/*/*/*/*',
        ]
    },
    description  = package_description,
    author       = "Gallopsled et al.",
    author_email = "#gallopsled @ freenode.net",
    url          = 'https://github.com/pwnies/pwntools/', # use the URL to the github repo
    scripts      = scripts,
    download_url = "https://github.com/pwnies/pwntools/tarball/master",
    requires     = ['paramiko','argparse', 'mako'],
    license      = "MIT",
    classifiers  = [
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers'
    ]
)
