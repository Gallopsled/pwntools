![pwntools logo](docs/source/logo.png?raw=true)

[![Docs latest](https://readthedocs.org/projects/pwntools/badge/)](https://pwntools.readthedocs.org/en/latest)
[![Docs 2.2.0](https://readthedocs.org/projects/pwntools/badge/?version=2.2.0)](https://pwntools.readthedocs.org/en/2.2.0)
[![PyPI](https://img.shields.io/pypi/v/pwntools.svg?style=flat)](https://pypi.python.org/pypi/pwntools/)
[![Gittip](https://img.shields.io/gittip/gallopsled.svg?style=flat)](https://www.gittip.com/gallopsled/)
[![Travis](https://travis-ci.org/Gallopsled/pwntools.svg)](https://travis-ci.org/Gallopsled/pwntools)
[![Twitter](https://img.shields.io/badge/twitter-Gallopsled-4099FF.svg?style=flat)](https://twitter.com/Gallopsled)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://choosealicense.com/licenses/mit/)

This is the CTF framework used by Gallopsled in every CTF.

```python
from pwn import *
context(arch = 'i386', os = 'linux')

r = remote('exploitme.example.com', 31337)
# EXPLOIT CODE GOES HERE
r.send(asm(shellcraft.sh()))
r.interactive()
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
Our documentation is available at [pwntools.readthedocs.org](https://pwntools.readthedocs.org/en/latest/)

To get you started, we've provided some example solutions for past CTF challenges in our [write-ups repository](https://github.com/Gallopsled/pwntools-write-ups).

# Installation

pwntools is best supported on Ubuntu 12.04 and 14.04, but most functionality should work on any Posix-like distribution (Debian, Arch, FreeBSD, OSX, etc.).

Most of the functionality of pwntools is self-contained and Python-only.  You should be able to get running quickly with

```sh
pip install pwntools
```

However, some of the features (ROP generation and assembling/disassembling foreign architectures) require non-Python dependencies.  For more information, see the [complete installation instructions here](https://pwntools.readthedocs.org/en/latest/install.html).


# Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md)

# Contact
If you have any questions not worthy of a [bug report](https://github.com/Gallopsled/pwntools/issues), feel free to join us
at [`#pwntools` on Freenode](irc://irc.freenode.net/pwntools) and ask away.
Click [here](https://kiwiirc.com/client/irc.freenode.net/pwntools) to connect.

