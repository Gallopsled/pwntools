.. testsetup:: *

   from pwn import *
   context.clear(arch='thumb')

   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['LINUX']

:mod:`pwnlib.shellcraft.thumb` --- Shellcode for Thumb Mode
===========================================================

:mod:`pwnlib.shellcraft.thumb`
-------------------------------

.. automodule:: pwnlib.shellcraft.thumb
   :members:

:mod:`pwnlib.shellcraft.thumb.linux`
---------------------------------------

.. automodule:: pwnlib.shellcraft.thumb.linux
   :members:
