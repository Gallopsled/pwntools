<% from pwnlib.shellcraft import arm %>
<%docstring>
Execute a different process.

.. doctest::
   :skipif: not binutils_arm or not qemu_arm

    >>> p = run_assembly(shellcraft.arm.linux.sh())
    >>> p.sendline('echo Hello')
    >>> p.recv()
    'Hello\n'

</%docstring>
    ${arm.linux.execve('/bin///sh', ['sh'], 0)}
