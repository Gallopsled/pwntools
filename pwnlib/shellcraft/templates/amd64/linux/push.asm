<%
  from pwnlib.shellcraft import amd64
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="value"/>
<%docstring>

Thin wrapper around :func:`pwnlib.shellcraft.amd64.push`, which sets
`context.os` to `'linux'` before calling.

Example:

    >>> print pwnlib.shellcraft.amd64.linux.push('SYS_execve').rstrip()
        /* push 'SYS_execve' */
        push 0x3b

</%docstring>

% with ctx.local(os = 'linux'):
  ${amd64.push(value)}
% endwith
