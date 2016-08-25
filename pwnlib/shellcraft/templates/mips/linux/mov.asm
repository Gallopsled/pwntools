<%
  from pwnlib.shellcraft import mips
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="dest, src"/>
<%docstring>

Thin wrapper around :func:`pwnlib.shellcraft.mips.mov`, which sets
`context.os` to `'linux'` before calling.

Example:

    >>> print pwnlib.shellcraft.mips.linux.mov('$a1', 'SYS_execve').rstrip()
        ori $a1, $zero, (SYS_execve)

</%docstring>

% with ctx.local(os = 'linux'):
  ${mips.mov(dest, src)}
% endwith
