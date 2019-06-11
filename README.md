# pwntools - CTF toolkit
![pwntools logo](https://github.com/Gallopsled/pwntools/blob/stable/docs/source/logo.png?raw=true)

[![Docs](https://readthedocs.org/projects/pwntools/badge/?version=stable)](https://docs.pwntools.com/)
[![PyPI](https://img.shields.io/badge/pypi-v3.12.1-green.svg?style=flat)](https://pypi.python.org/pypi/pwntools/)
[![Travis](https://travis-ci.org/Gallopsled/pwntools.svg)](https://travis-ci.org/Gallopsled/pwntools)
[![Coveralls](https://img.shields.io/coveralls/Gallopsled/pwntools/dev.svg)](https://coveralls.io/github/Gallopsled/pwntools?branch=dev)
[![Twitter](https://img.shields.io/badge/twitter-pwntools-4099FF.svg?style=flat)](https://twitter.com/pwntools)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://choosealicense.com/licenses/mit/)

Pwntools is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible.

```python
from pwn import *
context(arch = 'i386', os = 'linux')

r = remote('exploitme.example.com', 31337)
# EXPLOIT CODE GOES HERE
r.send(asm(shellcraft.sh()))
r.interactive()
```

# Try It Now!

You can now do a live demo of Pwntools, [right in your browser](https://demo.pwntools.com).

# Documentation

Our documentation is available at [docs.pwntools.com](https://docs.pwntools.com/)

To get you started, we've provided some example solutions for past CTF challenges in our [write-ups repository](https://github.com/Gallopsled/pwntools-write-ups).

# Installation

Pwntools is best supported on 64-bit Ubuntu LTE releases (12.04, 14.04, 16.04, 18.04).  Most functionality should work on any Posix-like distribution (Debian, Arch, FreeBSD, OSX, etc.). Unlike for mainstream pwntools, in Dev3 branch, Python 3 is expected.

Most of the functionality of pwntools is self-contained and Python-only.  You should be able to get running quickly with

```sh
# install bootstrap packages. Python 2.7 no longer required
apt-get update
apt-get install python-pip python-dev git libssl-dev libffi-dev build-essential

# Clone the repo
git clone https://github.com/Gallopsled/pwntools
cd pwntools

# switch to the hidden Dev3 branch
git branch -a
git checkout remotes/origin/dev3

# install the local dev3 branch
pip3 install .

# for whatever reason pip3 breaks after the installation.
# Reference: https://stackoverflow.com/questions/49836676/error-after-upgrading-pip-cannot-import-name-main
# Solution: to reinstall pip3
python3 -m pip uninstall pip && sudo apt install python3-pip --reinstall
```

However, some of the features (assembling/disassembling foreign architectures) require non-Python dependencies.  For more information, see the [complete installation instructions here](https://docs.pwntools.com/en/stable/install.html).


# Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md)

# Contact
If you have any questions not worthy of a [bug report](https://github.com/Gallopsled/pwntools/issues), feel free to ping us
at [`#pwntools` on Freenode](irc://irc.freenode.net/pwntools) and ask away.
Click [here](https://kiwiirc.com/client/irc.freenode.net/pwntools) to connect.
There is also a [mailing list](https://groups.google.com/forum/#!forum/pwntools-users) for higher latency discussion.
