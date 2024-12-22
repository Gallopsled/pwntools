.. testsetup:: *

   from pwnlib.runner import *
   from pwnlib.asm import asm

   # TODO: Remove global POSIX flag
   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['POSIX']

:mod:`pwnlib.runner` --- Running Shellcode
===========================================

.. automodule:: pwnlib.runner
   :members:
