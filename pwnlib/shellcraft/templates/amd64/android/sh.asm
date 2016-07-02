<% from pwnlib.shellcraft import amd64 %>
<%docstring>
Execute a different process.

    >>> p = run_assembly(shellcraft.amd64.linux.sh())
    >>> p.sendline('echo Hello')
    >>> p.recv()
    'Hello\n'

</%docstring>
${amd64.linux.execve('/system/bin//sh', ['sh'], 0)}
