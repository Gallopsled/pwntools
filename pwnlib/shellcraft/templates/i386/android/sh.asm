<% from pwnlib.shellcraft import i386 %>
<%docstring>
Execute a different process.

    >>> p = run_assembly(shellcraft.i386.linux.sh())
    >>> p.sendline('echo Hello')
    >>> p.recv()
    'Hello\n'

</%docstring>
${i386.linux.execve('/system/bin//sh', ['sh'], 0)}
