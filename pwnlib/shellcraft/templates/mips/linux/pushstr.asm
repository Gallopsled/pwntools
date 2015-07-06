<%
  from pwnlib.shellcraft import mips
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
%>
<%page args="string, append_null = True"/>
<%docstring>

Thin wrapper around :func:`pwnlib.shellcraft.mips.pushstr`, which sets
`context.os` to `'linux'` before calling.

Example:

    >>> print pwnlib.shellcraft.mips.linux.pushstr('Hello, World').rstrip()
        /* push 'Hello, World\x00' */
        .set noat
        slti $at, $zero, -1
        sw $at, -4($sp)
        add $sp, $sp, -4
        .set noat
        lui $at, 25708
        ori $at, $at, 29295
        sw $at, -4($sp)
        add $sp, $sp, -4
        .set noat
        lui $at, 22304
        ori $at, $at, 11375
        sw $at, -4($sp)
        add $sp, $sp, -4
        .set noat
        lui $at, 27756
        ori $at, $at, 25928
        sw $at, -4($sp)
        add $sp, $sp, -4

Args:
  string (str): The string to push.
  append_null (bool): Whether to append a single NULL-byte before pushing.
</%docstring>

% with ctx.local(os = 'linux'):
  ${mips.pushstr(string, append_null)}
% endwith
