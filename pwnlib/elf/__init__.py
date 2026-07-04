"""
Most exploitable CTF challenges are provided in the Executable and Linkable
Format (``ELF``).  Generally, it is very useful to be able to interact with
these files to extract data such as function addresses, ROP gadgets, and
writable page addresses.
"""
from pwnlib.elf.corefile import Core as Core
from pwnlib.elf.datatypes import *
from pwnlib.elf.elf import ELF as ELF
from pwnlib.elf.elf import load as load
from pwnlib.elf import maps as maps
from pwnlib.elf import plt as plt
