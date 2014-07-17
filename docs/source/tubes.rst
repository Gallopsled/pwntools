:mod:`pwnlib.tubes` --- Talking to the World!
=============================================

.. automodule:: pwnlib.tubes

   Sockets
   -------

   .. automodule:: pwnlib.tubes.remote

      .. autoclass:: pwnlib.tubes.remote.remote(host, port, fam = None, typ = None, proto = 0, timeout = 'default', log_level = INFO)
         :members:
         :show-inheritance:

   .. automodule:: pwnlib.tubes.listen

      .. autoclass:: pwnlib.tubes.listen.listen(port, bindaddr = "0.0.0.0", fam = "any", typ = "tcp", timeout = 'default', log_level = INFO)
         :members:
         :show-inheritance:

   .. automodule:: pwnlib.tubes.sock

      .. autoclass:: pwnlib.tubes.sock.sock()
         :members: shutdown
         :show-inheritance:

   Common functionality
   --------------------

   .. automodule:: pwnlib.tubes.tube

      .. autoclass:: pwnlib.tubes.tube.tube()
         :members:
         :exclude-members: recv_raw, send_raw, settimeout_raw,
                           can_recv_raw
