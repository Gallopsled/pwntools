.. testsetup:: *

    from pwn import *
    context.arch = 'amd64'
    context.terminal = [os.path.join(os.path.dirname(pwnlib.__file__), 'gdb_faketerminal.py')]
    context.log_level = 'debug'
    context.timeout = 5

:mod:`pwnlib.gdb` --- Working with GDB
======================================

.. automodule:: pwnlib.gdb
   :members:
