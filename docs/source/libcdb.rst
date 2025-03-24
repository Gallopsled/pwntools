.. testsetup:: *

   from pwn import *
   from pwnlib.libcdb import *

   # TODO: Remove global POSIX flag
   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['POSIX']

:mod:`pwnlib.libcdb` --- Libc Database
===========================================

.. automodule:: pwnlib.libcdb
   :members:
