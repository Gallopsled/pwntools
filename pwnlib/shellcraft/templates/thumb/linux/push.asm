<%
  from pwnlib.shellcraft import thumb
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="value"/>
<%docstring>

Thin wrapper around :func:`pwnlib.shellcraft.thumb.push`, which sets
`context.os` to `'linux'` before calling.

Example:

    >>> print pwnlib.shellcraft.thumb.linux.push('SYS_execve').rstrip()
        /* push 'SYS_execve' */
        mov r1, #11
        push {r1}

</%docstring>

% with ctx.local(os = 'linux'):
  ${thumb.push(value)}
% endwith
