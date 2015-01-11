<%
  from pwnlib.shellcraft import amd64
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="dest, src, stack_allowed = True"/>
<%docstring>

Thin wrapper around :func:`pwnlib.shellcraft.amd64.mov`, which sets
`context.os` to `'linux'` before calling.

Example:

    >>> print pwnlib.shellcraft.amd64.linux.mov('eax', 'SYS_execve').rstrip()
        push 0x3b
        pop rax

</%docstring>

% with ctx.local(os = 'linux'):
  ${amd64.mov(dest, src, stack_allowed)}
% endwith
