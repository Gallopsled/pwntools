#!/usr/bin/env python
from distutils.core import setup
import os, glob, time

package_name = "pwntools"
package_dir  = "pwntools"
package_description = """
This is the CTF framework used by pwnies in every CTF.
""".strip()


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

# Compile the list of packages available, because distutils doesn't have
# an easy way to do this.
packages, data_files = [], []
root_dir = os.path.dirname(__file__)
if root_dir != '':
    os.chdir(root_dir)

for dirpath, dirnames, filenames in os.walk(package_dir):
    # Ignore dirnames that start with '.'
    for i, dirname in enumerate(dirnames):
        if dirname.startswith('.'): del dirnames[i]
    if '__init__.py' in filenames:
        packages.append('.'.join(fullsplit(dirpath)))
    elif filenames:
        data_files.append([dirpath, [os.path.join(dirpath, f) for f in filenames]])

scripts = [
    'asm/asm',
    # 'bytes/bin/bytes',
    'clookup/clookup',
    # 'crop/bin/crop',
    'cyclic/cyclic',
    'demo/demo32',
    'demo/demo64',
    'dictgen/dictgen',
    'asm/disasm',
    'elfpatch/elfpatch',
    # 'gadgets/bin/gadgets',
    'hex/hex',
    # 'mags/bin/mags',
    'pbpoke/pbpoke.py',
    'pbpoke/pbpeek.py',
    'poke/poke',
    'poke/peek',
    'randomua/randomua',
    'scramble/scramble',
    'shellcraft/shellcraft',
    'hex/unhex',
]

setup(
    name            = package_name,
    version         = time.strftime('%Y.%m.%d'),
    description     = package_description,
    packages        = packages,
    license         = "MIT",
    author          = "pwnies",
    author_email    = "#gallopsled @ freenode.net",
    url             = "https://github.com/pwnies/pwntools",
    scripts         = scripts,
    download_url    = "https://github.com/pwnies/pwntools/tarball/master",
    requires        = ['paramiko','argparse'],
    classifiers     = [
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers'
    ]
)