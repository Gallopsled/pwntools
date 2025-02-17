.. testsetup:: *

   from pwn import *
   context.clear(arch='arm')

   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['LINUX']

:mod:`pwnlib.shellcraft.arm` --- Shellcode for ARM
===========================================================

:mod:`pwnlib.shellcraft.arm`
-----------------------------

.. automodule:: pwnlib.shellcraft.arm
   :members:

:mod:`pwnlib.shellcraft.arm.linux`
-----------------------------------

.. automodule:: pwnlib.shellcraft.arm.linux
   :members:
