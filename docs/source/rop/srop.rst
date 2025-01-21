.. testsetup:: *

   from pwnlib.rop.srop import *

   from pwnlib import constants
   from pwnlib import shellcraft
   from pwnlib.elf import ELF
   from pwnlib.tubes.process import process

   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['LINUX']

:mod:`pwnlib.rop.srop` --- Sigreturn Oriented Programming
==========================================================

.. automodule:: pwnlib.rop.srop
   :members:
