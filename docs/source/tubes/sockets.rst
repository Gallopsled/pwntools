.. testsetup:: *

   from pwn import *
   from pwnlib.tubes.server import server

   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['LINUX']

:mod:`pwnlib.tubes.sock` --- Sockets
===========================================================


.. automodule:: pwnlib.tubes.sock

   .. autoclass:: pwnlib.tubes.sock.sock()
      :show-inheritance:


.. automodule:: pwnlib.tubes.remote

   .. autoclass:: pwnlib.tubes.remote.remote
      :members:
      :show-inheritance:

.. automodule:: pwnlib.tubes.listen

   .. autoclass:: pwnlib.tubes.listen.listen
      :members:
      :show-inheritance:

.. automodule:: pwnlib.tubes.server

   .. autoclass:: pwnlib.tubes.server.server
      :members:
      :show-inheritance:
