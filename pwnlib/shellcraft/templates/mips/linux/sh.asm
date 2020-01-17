<% from pwnlib.shellcraft import mips %>
<%docstring>Execute /bin/sh

Example:

    >>> p = run_assembly(shellcraft.mips.linux.sh())
    >>> p.sendline(b'echo Hello')
    >>> p.recv()
    b'Hello\n'

</%docstring>

${mips.execve('//bin/sh', ['sh'], {})}
