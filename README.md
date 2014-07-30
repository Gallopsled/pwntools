# Introduction

This is the CTF framework used by Gallopsled in every CTF.

Most code is inside the pwnlib folder with some functionality inside pwn or
bin. It is typically used as:

```python
from pwn import *
context(arch = 'i386', os = 'linux')

# EXPLOIT HERE
```

However we have made command-line frontends for some of the functionality
inside the pwnlib. These are:

* `asm`/`disasm`: Small wrapper for various assemblers
* `cyclic`: De Bruijn sequence generator and lookup tool
* `constgrep`: Tool for finding constants defined in header files
* `shellcraft`: Frontend to our shellcode
* `hex`/`unhex`: Command line tools for doing common hexing/unhexing operations

# Documentation
Our documentation is available on http://pwntools.readthedocs.org/

# Installation
Pwntools is available as a pip package. You can install it by running
`pip install pwntools`.

Alternatively if you prefer to have the latest version in git, you can
simply clone this repository, run `pip install -r requirements.txt`
and add entries in your `PATH` and `PYTHONPATH` variables. The script
`install_local.sh` will help you do so, in case you are using bash.

# Contact
If you have any questions not worthy of a bug report, feel free to join us
at `#gallopsled` on Freenode and ask away.
