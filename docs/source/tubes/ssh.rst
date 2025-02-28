.. testsetup:: *

   from pwn import *

   # TODO: Remove global POSIX flag
   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['POSIX']

:mod:`pwnlib.tubes.ssh` --- SSH
===========================================================

.. automodule:: pwnlib.tubes.ssh

   .. autoclass:: pwnlib.tubes.ssh.ssh
      :members:

   .. autoclass:: pwnlib.tubes.ssh.ssh_channel()
      :members: kill, poll, interactive
      :show-inheritance:

   .. autoclass:: pwnlib.tubes.ssh.ssh_process
      :members:
      :show-inheritance:

   .. autoclass:: pwnlib.tubes.ssh.ssh_connecter()
      :show-inheritance:

   .. autoclass:: pwnlib.tubes.ssh.ssh_listener()
      :show-inheritance:
