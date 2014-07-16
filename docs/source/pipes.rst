:mod:`pwnlib.pipes` --- Talking to the World!
=============================================

.. automodule:: pwnlib.pipes

   Constructors
   ------------

   .. automodule:: pwnlib.pipes.remote

      .. autoclass:: pwnlib.pipes.remote.remote(host, port, fam = None, typ = None, proto = 0, timeout = 'default', log_level = INFO)
         :members:
         :show-inheritance:

   .. automodule:: pwnlib.pipes.listen

      .. autoclass:: pwnlib.pipes.listen.listen(port, bindaddr = "0.0.0.0", fam = "any", typ = "tcp", timeout = 'default', log_level = INFO)
         :members:
         :show-inheritance:

   Helper classes
   --------------

   .. automodule:: pwnlib.pipes.sock

      .. autoclass:: pwnlib.pipes.sock.sock()
         :members: shutdown
         :show-inheritance:

   .. automodule:: pwnlib.pipes.pipe

      .. autoclass:: pwnlib.pipes.pipe.pipe()
         :members:
         :exclude-members: recv_raw, send_raw, settimeout_raw,
                           can_recv_raw
