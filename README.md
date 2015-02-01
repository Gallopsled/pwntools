# binjitsu - CTF toolkit
[![Docs latest](https://readthedocs.org/projects/binjitsu/badge/)](https://binjitsu.readthedocs.org/en/latest)
[![Travis](https://travis-ci.org/binjitsu/binjitsu.svg)](https://travis-ci.org/binjitsu/binjitsu)
[![Twitter](https://img.shields.io/badge/twitter-ctfbinjitsu-4099FF.svg?style=flat)](https://twitter.com/ctfbinjitsu)

binjitsu is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible.

```python
from binjitsu import *
context(arch = 'i386', os = 'linux')

r = remote('exploitme.example.com', 31337)
# EXPLOIT CODE GOES HERE
r.send(asm(shellcraft.sh()))
r.interactive()
```

# Origin

binjitsu is a fork of the [`pwntools`](https://github.com/Gallopsled/pwntools) project.  For the most part, it's a drop-in replacement, though I've added some functionality of my own which may not be available in the upstream release.

# Documentation
Our documentation is available at [binjitsu.readthedocs.org](https://binjitsu.readthedocs.org/en/latest/)

To get you started, we've provided some example solutions for past CTF challenges in our [write-ups repository](https://github.com/binjitsu/binjitsu-write-ups).

# Installation

binjitsu is best supported on Ubuntu 12.04 and 14.04, but most functionality should work on any Posix-like distribution (Debian, Arch, FreeBSD, OSX, etc.).

Most of the functionality of binjitsu is self-contained and Python-only.  You should be able to get running quickly with

```sh
pip install --upgrade git+https://github.com/binjitsu/binjitsu
```

However, some of the features (ROP generation and assembling/disassembling foreign architectures) require non-Python dependencies.  For more information, see the [complete installation instructions here](https://binjitsu.readthedocs.org/en/latest/install.html).


# Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md)

# Contact
If you have any questions not worthy of a [bug report](https://github.com/binjitsu/binjitsu/issues), feel free to ping
at [`ebeip90` on Freenode](irc://irc.freenode.net/pwning) and ask away.
Click [here](https://kiwiirc.com/client/irc.freenode.net/pwning) to connect.


