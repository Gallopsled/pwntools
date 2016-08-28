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
        li $t1, 0x6c6c6548
        sw $t1, -16($sp)
        li $t1, 0x57202c6f
        sw $t1, -12($sp)
        li $t1, 0x646c726f
        sw $t1, -8($sp)
        sw $zero, -4($sp)
        addiu $sp, $sp, -16
Args:
  string (str): The string to push.
  append_null (bool): Whether to append a single NULL-byte before pushing.
</%docstring>

% with ctx.local(os = 'linux'):
  ${mips.pushstr(string, append_null)}
% endwith
