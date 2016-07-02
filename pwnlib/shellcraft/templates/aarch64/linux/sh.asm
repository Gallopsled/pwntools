<% from pwnlib.shellcraft import aarch64 %>
<%docstring>
Execute a different process.

    >>> p = run_assembly(shellcraft.aarch64.linux.sh())
    >>> p.sendline('echo Hello')
    >>> p.recv()
    'Hello\n'

</%docstring>
    ${aarch64.pushstr('/bin///sh')}
    ${aarch64.linux.execve('sp', 0, 0)}
