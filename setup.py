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
                        'capstone',
                        'ropgadget>=5.3',
                        'pyserial>=2.7',
                        'requests>=2.0',
                        'pip>=6.0.8',
                        'tox>=1.8.1',
                        'pygments>=2.0',
                        'pysocks',
                        'python-dateutil',
                        'pypandoc',
                        'packaging']

# This is a hack until somebody ports psutil to OpenBSD
if platform.system() != 'OpenBSD':
    install_requires.append('psutil>=2.1.3')

# Check that the user has installed the Python development headers
PythonH = os.path.join(get_python_inc(), 'Python.h')
if not os.path.exists(PythonH):
    print >> sys.stderr, "You must install the Python development headers!"
    print >> sys.stderr, "$ apt-get install python-dev"
    sys.exit(-1)

# Convert README.md to reStructuredText for PyPI
long_description = ''
try:
    import pypandoc
    try:
        pypandoc.get_pandoc_path()
    except OSError:
        pypandoc.download_pandoc()
    long_description = pypandoc.convert_file('README.md', 'rst')
except ImportError:
    pass


setup(
    name                 = 'pwntools',
    packages             = find_packages(),
    version              = '3.2.0beta2',
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
        ] + templates,
    },
    entry_points = {'console_scripts': console_scripts},
    scripts              = glob.glob("bin/*"),
    description          = "Pwntools CTF framework and exploit development library.",
    long_description     = long_description,
    author               = "Gallopsled et al.",
    author_email         = "#pwntools @ freenode.net",
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
