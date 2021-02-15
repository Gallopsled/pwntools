.. testsetup:: *

    from pwn import *
    context.clear()
    context.arch = 'amd64'
    context.log_console = sys.stderr
    context.log_level = 'debug'
    # context.terminal = [os.path.join(os.path.dirname(pwnlib.__file__), 'gdb_faketerminal.py')]

:mod:`pwnlib.gdb` --- Working with GDB
======================================

.. automodule:: pwnlib.gdb
   :members:
