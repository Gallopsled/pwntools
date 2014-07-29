#!/usr/bin/env python
from setuptools import setup, find_packages
import os, sys, glob

templates = []
for dirpath, dirnames, filenames in os.walk(os.path.join('pwnlib', 'shellcraft', 'templates')):
    for f in filenames:
        templates.append(os.path.relpath(os.path.join(dirpath, f), 'pwnlib'))

setup(
    name                 = 'pwntools',
    packages             = find_packages(),
    version              = '2.1.0',
    package_data         = {
        'pwnlib': [
            'data/crcsums.txt',
            'data/binutils/*',
            'data/includes/*.h',
            'data/includes/*/*.h',
        ] + templates
    },
    scripts              = glob.glob("bin/*"),
    description          = "This is the CTF framework used by Gallopsled in every CTF.",
    author               = "Gallopsled et al.",
    author_email         = "#gallopsled @ freenode.net",
    url                  = 'https://github.com/pwnies/pwntools/', # use the URL to the github repo
    download_url         = "https://github.com/pwnies/pwntools/tarball/master",
    install_requires     = ['paramiko','argparse', 'mako'],
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
