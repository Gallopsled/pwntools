.. testsetup:: *

   from pwn import *

   # TODO: Remove global POSIX flag
   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['POSIX']

:mod:`pwnlib.tubes.serialtube` --- Serial Ports
===========================================================

.. automodule:: pwnlib.tubes.serialtube

   .. autoclass:: pwnlib.tubes.serialtube.serialtube
      :members:
