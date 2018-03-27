<% from pwnlib.shellcraft import thumb %>
<%docstring>
Execute a different process.

    >>> p = run_assembly(shellcraft.thumb.linux.sh())
    >>> p.sendline(b'echo Hello')
    >>> p.recv()
    'Hello\n'

</%docstring>
${thumb.linux.execve('/bin///sh', ['sh'], 0)}
