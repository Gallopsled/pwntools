<%
  from pwnlib.shellcraft import i386
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="value"/>
<%docstring>

Thin wrapper around :func:`pwnlib.shellcraft.i386.push`, which sets
`context.os` to `'linux'` before calling.

Example:

    >>> print pwnlib.shellcraft.i386.linux.push('SYS_execve').rstrip()
        /* push (SYS_execve) (0xb) */
        push 0xb

</%docstring>

% with ctx.local(os = 'linux'):
  ${i386.push(value)}
% endwith
