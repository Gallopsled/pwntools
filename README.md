# Introduction

This is the CTF framework used by pwnies in every CTF.

Most code is inside the pwnlib folder with some functionality inside pwn or bin. It is typically used as:

```python
from pwn import *
context(arch = 'i386', os = 'linux')

# EXPLOIT HERE
```

However we have made command-line frontends for much of the functionality
inside the pwnlib. These are:

* `asm`/`disasm`: Small wrapper for nasm
* `cyclic`: De Bruijn sequence generator and lookup tool
* `shellcraft`: Frontend to our shellcode

We also have the following tools, not dependent on the pwnlib:

*  binutils directory: Assemblers and disassemblers for various architectures
* `hex`/`unhex`: Command line tools for doing common hexing/unhexing operations

# Documentation
Our documentation is available on

# Installation
Pwntools is available as a pip package. You can install it by running
`pip install pwntools`.

Alternatively if you prefer to have the latest version in git, you can
simply clone this repository, run `pip install -r requirements.txt`
and entries in your `PATH` and `PYTHONPATH` variables. The script
`install_local.sh` will help you do so, in case you are using bash.

# Contact
If you have any questions not worthy of a bug report, feel free to join us
at `#gallopsled` on Freenode and ask away.
