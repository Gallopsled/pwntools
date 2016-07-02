<%
  from pwnlib.shellcraft import i386
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="value"/>
<%docstring>

Thin wrapper around :func:`pwnlib.shellcraft.i386.push`, which sets
`context.os` to `'freebsd'` before calling.

Example:

    >>> print pwnlib.shellcraft.i386.freebsd.push('SYS_execve').rstrip()
        /* push (SYS_execve) (0x3b) */
        push 0x3b

</%docstring>

% with ctx.local(os = 'freebsd'):
  ${i386.push(value)}
% endwith
