.. testsetup:: *

   from pwn import *

   # TODO: Remove global POSIX flag
   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['POSIX']
   
:mod:`pwnlib.encoders` --- Encoding Shellcode
===============================================

.. automodule:: pwnlib.encoders.encoder
   :members:

.. automodule:: pwnlib.encoders.i386.ascii_shellcode
   :members:
   :special-members:
   :exclude-members: __init__

.. automodule:: pwnlib.encoders.i386.xor
   :members:

.. automodule:: pwnlib.encoders.i386.delta
   :members:

.. automodule:: pwnlib.encoders.amd64.delta
   :members:

.. automodule:: pwnlib.encoders.arm.xor
   :members:

.. automodule:: pwnlib.encoders.mips.xor
   :members:
