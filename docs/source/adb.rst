.. testsetup:: *

   from pprint import pprint
   from pwn import *
   adb = pwnlib.adb

   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['LINUX']

:mod:`pwnlib.adb` --- Android Debug Bridge
=====================================================

.. automodule:: pwnlib.adb.adb
   :members:

.. automodule:: pwnlib.adb.protocol
   :members:
