.. testsetup:: *

   from pwnlib.tubes.tube import tube
   from pwnlib.tubes.ssh import *
   from pwnlib.tubes.remote import remote
   from pwnlib.util.misc import which

:mod:`pwnlib.tubes` --- Talking to the World!
=============================================

.. automodule:: pwnlib.tubes

   Sockets
   -------

   .. automodule:: pwnlib.tubes.remote

      .. autoclass:: pwnlib.tubes.remote.remote
         :members:
         :show-inheritance:

   .. automodule:: pwnlib.tubes.listen

      .. autoclass:: pwnlib.tubes.listen.listen
         :members:
         :show-inheritance:

   .. automodule:: pwnlib.tubes.sock

      .. autoclass:: pwnlib.tubes.sock.sock()
         :show-inheritance:

   Processes
   ---------

   .. automodule:: pwnlib.tubes.process

      .. autoclass:: pwnlib.tubes.process.process
         :members: kill, poll, communicate
         :show-inheritance:

   SSH
   ---

   .. automodule:: pwnlib.tubes.ssh

      .. autoclass:: pwnlib.tubes.ssh.ssh
         :members:

      .. autoclass:: pwnlib.tubes.ssh.ssh_channel()
         :members: kill, poll, interactive
         :show-inheritance:

      .. autoclass:: pwnlib.tubes.ssh.ssh_connecter()
         :show-inheritance:

      .. autoclass:: pwnlib.tubes.ssh.ssh_listener()
         :show-inheritance:

   Common functionality
   --------------------

   .. automodule:: pwnlib.tubes.tube

      .. autoclass:: pwnlib.tubes.tube.tube()
         :members:
         :exclude-members: recv_raw, send_raw, settimeout_raw,
                           can_recv_raw
