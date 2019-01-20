<% from pwnlib.shellcraft import mips %>
<%docstring>Execute /bin/sh

Example:

.. doctest::
   :skipif: not binutils_aarch64 or not qemu_aarch64

    >>> p = run_assembly(shellcraft.mips.linux.sh())
    >>> p.sendline('echo Hello')
    >>> p.recv()
    'Hello\n'

</%docstring>

${mips.execve('//bin/sh', ['sh'], {})}
