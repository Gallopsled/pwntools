.. testsetup:: *

    from pwn import *
    context.arch = 'amd64'
    context.terminal = [os.path.join(os.path.dirname(pwnlib.__file__), 'gdb_faketerminal.py')]

:mod:`pwnlib.gdb` --- Working with GDB
======================================

.. automodule:: pwnlib.gdb
   :members:
