<% from pwnlib.shellcraft import mips %>
<%docstring>Execute /bin/sh

Example:

    >>> p = run_assembly(shellcraft.mips.linux.sh())
    >>> p.sendline('echo Hello')
    >>> p.recv()
    'Hello\n'

</%docstring>

${mips.execve('//bin/sh', ['sh'], {})}
