.. testsetup:: *

   import tempfile

   from pwnlib import shellcraft

   from pwnlib.asm import asm
   from pwnlib.context import context
   from pwnlib.runner import run_assembly
   from pwnlib.util.fiddling import enhex
   from pwnlib.util.misc import write

   context.clear(arch='mips')

:mod:`pwnlib.shellcraft.mips` --- Shellcode for MIPS
===========================================================

:mod:`pwnlib.shellcraft.mips`
-----------------------------

.. automodule:: pwnlib.shellcraft.mips
   :members:

:mod:`pwnlib.shellcraft.mips.linux`
-----------------------------------

.. automodule:: pwnlib.shellcraft.mips.linux
   :members:
