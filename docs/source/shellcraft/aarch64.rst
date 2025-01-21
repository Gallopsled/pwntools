.. testsetup:: *

   from pwn import *
   context.clear(arch='aarch64')

   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['LINUX']

:mod:`pwnlib.shellcraft.aarch64` --- Shellcode for AArch64
===========================================================

:mod:`pwnlib.shellcraft.aarch64`
--------------------------------

.. automodule:: pwnlib.shellcraft.aarch64
   :members:

:mod:`pwnlib.shellcraft.aarch64.linux`
--------------------------------------

.. automodule:: pwnlib.shellcraft.aarch64.linux
   :members:
