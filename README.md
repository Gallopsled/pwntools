# pwntools - CTF toolkit
[![Docs latest](https://readthedocs.org/projects/pwntools/badge/)](http://pwntools.readthedocs.org/en/latest)
[![Docs 2.1.3](https://readthedocs.org/projects/pwntools/badge/?version=2.1.3)](http://pwntools.readthedocs.org/en/2.1.3)
[![PyPI](http://img.shields.io/pypi/v/pwntools.svg)](https://pypi.python.org/pypi/pwntools/)
[![Gittip](http://img.shields.io/gittip/gallopsled.svg)](https://www.gittip.com/gallopsled/)

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
Our documentation is available at http://pwntools.readthedocs.org/

To get you started, we've provided some example solutions for past CTF challenges in our [write-ups repository](https://github.com/Gallopsled/pwntools-write-ups).

# Installation

Pwntools is available as a pip package. You can install it and dependencies with a single command:

```sh
pip2 install pwntools
```

Alternatively if you prefer to use the latest version from the repository:

```sh
git clone https://github.com/Gallopsled/pwntools
cd pwntools
pip2 install -r requirements.txt
PWN=$(realpath .)
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
If you have any questions not worthy of a bug report, feel free to join us
at `#gallopsled` on Freenode and ask away.
