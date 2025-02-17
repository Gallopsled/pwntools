.. testsetup:: *

   from pwn import *
   context.clear(arch='amd64')

   # TODO: POSIX/WINDOWS shellcode test
   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['LINUX']

:mod:`pwnlib.shellcraft.amd64` --- Shellcode for AMD64
===========================================================

:mod:`pwnlib.shellcraft.amd64`
---------------------------------------

.. automodule:: pwnlib.shellcraft.amd64
   :members:

:mod:`pwnlib.shellcraft.amd64.linux`
---------------------------------------

.. automodule:: pwnlib.shellcraft.amd64.linux
   :members:

:mod:`pwnlib.shellcraft.amd64.windows`
---------------------------------------

.. automodule:: pwnlib.shellcraft.amd64.windows
   :members:
