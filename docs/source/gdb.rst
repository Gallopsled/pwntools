.. testsetup:: *

    from pwn import *
    context.arch = 'amd64'
    context.terminal = [os.path.join(os.path.dirname(pwnlib.__file__), 'gdb_faketerminal.py')]

    # TODO: Test on cygwin too
    import doctest
    doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['POSIX']

:mod:`pwnlib.gdb` --- Working with GDB
======================================

.. automodule:: pwnlib.gdb
   :members:
