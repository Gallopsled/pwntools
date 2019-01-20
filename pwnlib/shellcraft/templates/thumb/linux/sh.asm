<% from pwnlib.shellcraft import thumb %>
<%docstring>
Execute a different process.

.. doctest::
   :skipif: not binutils_aarch64 or not qemu_aarch64

    >>> p = run_assembly(shellcraft.thumb.linux.sh())
    >>> p.sendline('echo Hello')
    >>> p.recv()
    'Hello\n'

</%docstring>
${thumb.linux.execve('/bin///sh', ['sh'], 0)}
