<% from pwnlib.shellcraft import arm %>
<%docstring>
Execute a different process.

    >>> p = run_assembly(shellcraft.arm.linux.sh())
    >>> p.sendline('echo Hello')
    >>> p.recv()
    'Hello\n'

</%docstring>
    ${arm.linux.execve('/system/bin//sh', ['sh'], 0)}
