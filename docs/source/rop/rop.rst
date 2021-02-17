.. testsetup:: *

   import time
   from glob import glob

   from pwnlib.asm import asm
   from pwnlib import constants
   from pwnlib.context import context
   from pwnlib.elf import ELF
   from pwnlib.rop import ROP
   from pwnlib.rop.call import Call, AppendedArgument
   from pwnlib.elf.maps import CAT_PROC_MAPS_EXIT
   from pwnlib.util.packing import *
   from pwnlib.util.fiddling import *
   from pwnlib.tubes.process import process
   from pwnlib import shellcraft
   from pwnlib.util.misc import which

   context.clear()


:mod:`pwnlib.rop.rop` --- Return Oriented Programming
==========================================================

.. automodule:: pwnlib.rop.rop
   :members:
