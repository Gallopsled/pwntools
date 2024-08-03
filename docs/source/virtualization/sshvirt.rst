.. testsetup:: *

    from pwn import *
    context.arch = 'amd64'
    context.terminal = [os.path.join(os.path.dirname(pwnlib.__file__), 'gdb_faketerminal.py')]

:mod:`pwnlib.virtualization.sshvirt` --- Working with Sshvirt
===============================================================

.. automodule:: pwnlib.virtualization.sshvirt
   :members:
