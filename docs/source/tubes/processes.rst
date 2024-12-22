.. testsetup:: *

   from pwn import *

   # TODO: Remove global POSIX flag
   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['POSIX']

:mod:`pwnlib.tubes.process` --- Processes
===========================================================

.. automodule:: pwnlib.tubes.process

  .. autoclass:: pwnlib.tubes.process.process
     :members:
     :show-inheritance:
