# pwntools - CTF toolkit
[![Docs latest](https://readthedocs.org/projects/pwntools/badge/)](http://pwntools.readthedocs.org/en/latest)
[![Docs 2.1.3](https://readthedocs.org/projects/pwntools/badge/?version=2.1.3)](http://pwntools.readthedocs.org/en/2.1.3)
[![PyPI](http://img.shields.io/pypi/v/pwntools.svg)](https://pypi.python.org/pypi/pwntools/)
[![Gittip](http://img.shields.io/gittip/gallopsled.svg)](https://www.gittip.com/gallopsled/)
[![Travis](https://travis-ci.org/Gallopsled/pwntools.svg)](https://travis-ci.org/Gallopsled/pwntools)

This is the CTF framework used by Gallopsled in every CTF.

Most code is inside the `pwnlib` folder with some functionality inside `pwn` or
`bin`. It is typically used as:

```python
from pwn import *
context(arch = 'i386', os = 'linux')

# EXPLOIT HERE
```

However we have made command-line frontends for some of the functionality
in `pwnlib`. These are:

* `asm`/`disasm`: Small wrapper for various assemblers.
* `constgrep`: Tool for finding constants defined in header files.
* `cyclic`: De Bruijn sequence generator and lookup tool.
* `hex`/`unhex`: Command line tools for doing common hexing/unhexing operations.
* `shellcraft`: Frontend to our shellcode.
* `phd`: Replacement for `hexdump` with colors.

# Documentation
Our documentation is available at http://docs.pwntools.com

To get you started, we've provided some example solutions for past CTF challenges in our [write-ups repository](https://github.com/Gallopsled/pwntools-write-ups).

# Installation

pwntools is best supported on Ubuntu 12.04 and 14.04, but most functionality should work on any Posix-like distribution (Debian, Arch, FreeBSD, OSX, etc.).

## Prerequisites

In order to get the most out of `pwntools`, you should have the following system libraries installed.

- binutils for your target architecture ([Ubuntu][ppa])
- [libcapstone 2.1][capstone] (Ubuntu [i386][i386] [amd64][amd64])

[capstone]: http://www.capstone-engine.org
[ppa]: https://launchpad.net/~pwntools/+archive/ubuntu/binutils
[i386]: http://www.capstone-engine.org/download/2.1.2/capstone-2.1.2_i386.deb
[amd64]: http://www.capstone-engine.org/download/2.1.2/capstone-2.1.2_amd64.deb

## Released Versionr

Pwntools is available as a pip package. It reqiures Python 2.7, and one of its dependences requires the Python headers.

```sh
apt-get install python2.7 python2.7-dev python-pip
pip install pwntools
```

## Latest Version

Alternatively if you prefer to use the latest version from the repository:

```sh
git clone https://github.com/Gallopsled/pwntools
PWN=$(realpath pwntools)
cd $PWN
pip2 install -r requirements.txt
export PATH="$PWN/bin:$PATH"
export PYTHONPATH="$PWN:$PYTHONPATH"
```

If you want to make these settings permanent:

```sh
>>~/.bashrc cat <<EOF
# Set up path for Pwntools
export PATH="$PWN/bin:\$PATH"
export PYTHONPATH="$PWN:\$PYTHONPATH"
EOF
```

# Contact
If you have any questions not worthy of a [bug report](https://github.com/Gallopsled/pwntools/issues), feel free to join us
at [`#gallopsled` on Freenode](irc://irc.freenode.net/gallopsled) and ask away.
Click [here](https://kiwiirc.com/client/irc.freenode.net/gallopsled) to connect.

