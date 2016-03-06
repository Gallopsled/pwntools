<%
  from pwnlib.shellcraft import thumb
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="dest, src"/>
<%docstring>

Thin wrapper around :func:`pwnlib.shellcraft.thumb.mov`, which sets
`context.os` to `'linux'` before calling.

Example:

    >>> print pwnlib.shellcraft.thumb.linux.mov('r1', 'SYS_execve').rstrip()
        mov r1, #SYS_execve

</%docstring>

% with ctx.local(os = 'linux'):
  ${thumb.mov(dest, src)}
% endwith
