#!/usr/bin/env python
from setuptools import setup, find_packages
import os, sys

# Ugly hack to make sure that the templates have been built when running sdist
# If anybody knows a better way to do this, please let us know!
def fix_templates():
    try:
        import mako
    except:
        os.system("sudo pip install mako")
    def walker(val):
        for k in dir(val):
            if not k or k[0] == '_':
                continue
            nextval = getattr(val, k)
            import types
            if isinstance(nextval, types.ModuleType):
                walker(nextval)
    sys.path.append(os.getcwd())
    import pwnlib.shellcraft
    walker(pwnlib.shellcraft)
    for dirpath, dirnames, filenames in os.walk(os.path.join('pwnlib', 'shellcraft', 'pycs')):
        open(os.path.join(dirpath, '__init__.py'), 'w')


if not os.path.isfile(os.path.join('pwnlib', 'shellcraft', 'pycs', '__init__.py')):
    fix_templates()

templates = []
for dirpath, dirnames, filenames in os.walk(os.path.join('pwnlib', 'shellcraft', 'templates')):
    for f in filenames:
        templates.append(os.path.relpath(os.path.join(dirpath, f), 'pwnlib'))

setup(
    name                 = 'pwntools',
    packages             = find_packages(),
    version              = '2.0',
    package_data         = {
        'pwnlib': [
            'data/crcsums.txt',
            'data/binutils/*',
            'data/includes/*.h',
            'data/includes/*/*.h',
        ] + templates
    },
    scripts              = [
        'bin/asm',
        'bin/cyclic',
        'bin/disasm',
        'bin/hex',
        'bin/shellcraft',
        'bin/unhex',
    ],
    description          = "This is the CTF framework used by Gallopsled in every CTF.",
    author               = "Gallopsled et al.",
    author_email         = "#gallopsled @ freenode.net",
    url                  = 'https://github.com/pwnies/pwntools/', # use the URL to the github repo
    download_url         = "https://github.com/pwnies/pwntools/tarball/master",
    install_requires     = ['paramiko','argparse', 'mako'],
    setup_requires       = ['mako'],
    license              = "MIT",
    classifiers          = [
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers'
    ]
)
