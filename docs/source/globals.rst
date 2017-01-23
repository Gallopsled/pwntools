.. testsetup:: *

   from pwn import *

``from pwn import *``
========================

The most common way that you'll see pwntools used is

    >>> from pwn import *

Which imports a bazillion things into the global namespace to make your life easier.

This is a quick list of most of the objects and routines imported, in rough order of importance and frequency of use.

- :obj:`.context`
    - :data:`pwnlib.context.context`
    - Responsible for most of the pwntools convenience settings
    - Set `context.log_level = 'debug'` when troubleshooting your exploit
    - Scope-aware, so you can disable logging for a subsection of code via :meth:`.ContextType.local`
- ``remote``, ``listen``, ``ssh``, ``process``
    - :mod:`pwnlib.tubes`
    - Super convenient wrappers around all of the common functionality for CTF challenges
    - Connect to anything, anywhere, and it works the way you want it to
    - Helpers for common tasks like ``recvline``, ``recvuntil``, ``clean``, etc.
    - Interact directly with the application via ``.interactive()``
- ``p32`` and ``u32``
    - :mod:`pwnlib.util.packing`
    - Useful functions to make sure you never have to remember if ``'>'`` means signed or unsigned for ``struct.pack``, and no more ugly ``[0]`` index at the end.
    - Set ``signed`` and ``endian`` in sane manners (also these can be set once on ``context`` and not bothered with again)
    - Most common sizes are pre-defined (``u8``, ``u64``, etc), and :func:`pwnlib.util.packing.pack` lets you define your own.
- ``log``
    - :mod:`pwnlib.log`
    - Make your output pretty!
- ``cyclic`` and ``cyclic_func``
    - :mod:`pwnlib.util.cyclic`
    - Utilities for generating strings such that you can find the offset of any given substring given only N (usually 4) bytes.  This is super useful for straight buffer overflows.  Instead of looking at 0x41414141, you could know that 0x61616171 means you control EIP at offset 64 in your buffer.
- ``asm`` and ``disasm``
    - :mod:`pwnlib.asm`
    - Quickly turn assembly into some bytes, or vice-versa, without mucking about
    - Supports any architecture for which you have a binutils installed
    - Over 20 different architectures have pre-built binaries at `ppa:pwntools/binutils <https://launchpad.net/~pwntools/+archive/ubuntu/binutils>`_.
- ``shellcraft``
    - :mod:`pwnlib.shellcraft`
    - Library of shellcode ready to go
    - ``asm(shellcraft.sh())`` gives you a shell
    - Templating library for reusability of shellcode fragments
- ``ELF``
    - :mod:`pwnlib.elf`
    - ELF binary manipulation tools, including symbol lookup, virtual memory to file offset helpers, and the ability to modify and save binaries back to disk
- ``DynELF``
    - :mod:`pwnlib.dynelf`
    - Dynamically resolve functions given only a pointer to any loaded module, and a function which can leak data at any address
- ``ROP``
    - :mod:`pwnlib.rop`
    - Automatically generate ROP chains using a DSL to describe what you want to do, rather than raw addresses
- ``gdb.debug`` and ``gdb.attach``
    - :mod:`pwnlib.gdb`
    - Launch a binary under GDB and pop up a new terminal to interact with it.  Automates setting breakpoints and makes iteration on exploits MUCH faster.
    - Alternately, attach to a running process given a PID, :mod:`pwnlib.tubes` object, or even just a socket that's connected to it
- ``args``
    - Dictionary containing all-caps command-line arguments for quick access
    - Run via ``python foo.py REMOTE=1`` and ``args['REMOTE'] == '1'``.
    - Can also control logging verbosity and terminal fanciness
        - `NOTERM`
        - `SILENT`
        - `DEBUG`
- ``randoms``, ``rol``, ``ror``, ``xor``, ``bits``
    - :mod:`pwnlib.util.fiddling`
    - Useful utilities for generating random data from a given alphabet, or simplifying math operations that usually require masking off with `0xffffffff` or calling `ord` and `chr` an ugly number of times
- ``net``
    - :mod:`pwnlib.util.net`
    - Routines for querying about network interfaces
- ``proc``
    - :mod:`pwnlib.util.proc`
    - Routines for querying about processes
- ``pause``
    - It's the new ``getch``
- ``safeeval``
    - :mod:`pwnlib.util.safeeval`
    - Functions for safely evaluating python code without nasty side-effects.

These are all pretty self explanatory, but are useful to have in the global namespace.

- ``hexdump``
- ``read`` and ``write``
- ``enhex`` and ``unhex``
- ``more``
- ``group``
- ``align`` and ``align_down``
- ``urlencode`` and ``urldecode``
- ``which``
- ``wget``

Additionally, all of the following modules are auto-imported for you.  You were going to do it anyway.

- ``os``
- ``sys``
- ``time``
- ``requests``
- ``re``
- ``random``
