.. testsetup:: *

   import tempfile
   import subprocess
   from pwnlib.context import context
   from pwnlib.asm import *
   from pwnlib import shellcraft
   from pwnlib.tubes.process import process
   from pwnlib.util.fiddling import unhex


:mod:`pwnlib.asm` --- Assembler functions
=========================================

.. automodule:: pwnlib.asm
   :members:

Internal Functions
-----------------------------------------

These are only included so that their tests are run.

You should never need these.

.. autofunction:: pwnlib.asm.dpkg_search_for_binutils
.. autofunction:: pwnlib.asm.print_binutils_instructions
