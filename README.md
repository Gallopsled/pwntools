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

# Installation
To install it, just update your `PYTHONPATH` and `PATH` variables. Alternatively
you can run `python setup.py install`.

# Contact
If you have any questions not worthy of a bug report, feel free to join us
at `#gallopsled` on Freenode and ask away.
