<% from pwnlib.shellcraft import i386 %>
<%docstring>
Execute a different process.

.. doctest::
   :skipif: not binutils_i386 or not qemu_i386

    >>> p = run_assembly(shellcraft.i386.linux.sh())
    >>> p.sendline('echo Hello')
    >>> p.recv()
    'Hello\n'

</%docstring>
${i386.linux.execve('/bin///sh', ['sh'], 0)}
