<%
  from pwnlib.shellcraft import i386
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="dest, src, stack_allowed = True"/>
<%docstring>

Thin wrapper around :func:`pwnlib.shellcraft.i386.mov`, which sets
`context.os` to `'freebsd'` before calling.

Example:

    >>> print pwnlib.shellcraft.i386.freebsd.mov('eax', 'SYS_execve').rstrip()
        push (SYS_execve) /* 0x3b */
        pop eax

</%docstring>

% with ctx.local(os = 'freebsd'):
  ${i386.mov(dest, src, stack_allowed)}
% endwith
