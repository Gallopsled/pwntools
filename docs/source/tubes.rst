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
         :show-inheritance:

   Processes
   ---------

   .. automodule:: pwnlib.tubes.process

      .. autoclass:: pwnlib.tubes.process.process(args, shell = False, executable = None, env = None, timeout = 'default', log_level = INFO)
         :members: kill, poll, communicate
         :show-inheritance:

   SSH
   ---

   .. automodule:: pwnlib.tubes.ssh

      .. autoclass:: pwnlib.tubes.ssh.ssh(user, host, port = 22, password = None, key = None, keyfile = None, proxy_command = None, proxy_sock = None, timeout = 'default', log_level = INFO)
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
