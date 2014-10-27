.. testsetup:: *

   from pwnlib.asm import *
   from pwnlib import shellcraft

:mod:`pwnlib.asm` --- Assembler functions
=========================================

Utilities for assembling and disassembling code.

Architecture Selection
------------------------

    Architecture, endianness, and word size are selected by using :mod:`pwnlib.context`.

    Any parameters which can be specified to ``context`` can also be specified as
    keyword arguments to either :func:`asm` or :func:`disasm`.

Assembly
------------------------

    To assemble code, simply invoke :func:`asm` on the code to assemble.

        >>> asm('mov eax, 0')
        '\xb8\x00\x00\x00\x00'

    Additionally, you can use constants as defined in the :mod:`pwnlib.constants`
    module.

        >>> asm('mov eax, SYS_execve')
        '\xb8\x0b\x00\x00\x00'

    Finally, :func:`asm` is used to assemble shellcode provided by ``pwntools``
    in the :mod:`shellcraft` module.

        >>> asm(shellcraft.sh())
        '1\xc9\xf7\xe9j\x01\xfe\x0c$h//shh/bin\xb0\x0b\x89\xe3\xcd\x80'

Disassembly
------------------------

    To disassemble code, simply invoke :func:`disasm` on the bytes to disassemble.

    >>> disasm('\xb8\x0b\x00\x00\x00')
    '   0:   b8 0b 00 00 00          mov    eax,0xb'


Module Documentation
^^^^^^^^^^^^^^^^^^^^
.. automodule:: pwnlib.asm
   :members:
