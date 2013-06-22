# Introduction

This is the CTF framework used by pwnies in every CTF.

Most code is inside the pwn folder, which is typically used as:

```python
from pwn import *
context('i386', 'linux')

# EXPLOIT HERE
```

However we have made command-line frontends for much of the functionality
inside the pwnlib. These are:

* `asm`/`disasm`: Small wrapper for nasm
* `clookup`: Tool for looking up constants (such as SYS_open) on various os/architecture combinations.
* `cyclic`: De Bruijn sequence generator and lookup tool
* `nops`: Tool for generating random nopsleds.
* `peek`/`poke`: Simple tool for sending files over a LAN
* `randomua`: Returns a random user agent
* `scramble`: Shellcode packer
* `shellcraft`: Frontend to our shellcode

We also have the following tools, not dependent on the pwnlib:

*  binutils directory: Assemblers and disassemblers for various architectures
* `bytes`: Extract the raw bytes from various textual representations
* `crop`: Cut out rectangular portions of text
* `demo32`/`demo64`: Tool for testing shellcode
* `dictgen`: Generate dictionaries from input corpora
* `gadgets`: Find ROP gadgets
* `hex`/`unhex`: Command line tools for doing common hexing/unhexing operations
* `mags`: Run `file` at all offsets

All of these tools are symlinked to the bin folder.

# Installation
To install it, just update your `PYTHONPATH` and `PATH` variables. Alternatively
you can run `install.sh`.

## Dependencies

### Python libraries
```
crypto
gmpy
sympy
matplotlib
```

### Haskell libraries
The following libraries may be installed using `cabal`.

```
disassembler
elf
```

### All of the above
`apt-get install cabal-install python-sympy python-matplotlib
python-gmpy python-crypto && cabal
update && cabal install disassembler elf`

# Contact
If you have any questions not worthy of a bug report, feel free to join us
at `#zomg_pwnies` on Freenode and ask away.
