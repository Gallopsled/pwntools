<%
  from pwnlib.util import packing
  from pwnlib.shellcraft import i386
  from pwnlib import constants
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  import re
%>
<%page args="value"/>
<%docstring>
Pushes a value onto the stack without using
null bytes or newline characters.

If src is a string, then we try to evaluate with `context.arch = 'i386'` using
:func:`pwnlib.constants.eval` before determining how to push it. Note that this
means that this shellcode can change behavior depending on the value of
`context.os`.

Args:
  value (int,str): The value or register to push

Example:

    >>> print pwnlib.shellcraft.i386.push(0).rstrip()
        /* push 0 */
        push 0x1
        dec byte ptr [esp]
    >>> print pwnlib.shellcraft.i386.push(1).rstrip()
        /* push 1 */
        push 0x1
    >>> print pwnlib.shellcraft.i386.push(256).rstrip()
        /* push 256 */
        push 0x1010201
        xor dword ptr [esp], 0x1010301
    >>> with context.local(os = 'linux'):
    ...     print pwnlib.shellcraft.i386.push('SYS_execve').rstrip()
        /* push 'SYS_execve' */
        push 0xb
    >>> with context.local(os = 'freebsd'):
    ...     print pwnlib.shellcraft.i386.push('SYS_execve').rstrip()
        /* push 'SYS_execve' */
        push 0x3b
</%docstring>

<%
  value_orig = value
  # There are no meaningful constants of length < 3.
  # There are however constants such as EBP, which we would
  # prefer to avoid.
  if isinstance(value, (str, unicode)) and len(value) > 3:
    try:
      with ctx.local(arch = 'i386'):
        value = constants.eval(value)
    except (ValueError, AttributeError):
      pass
%>

% if isinstance(value, (int,long)):
    /* push ${repr(value_orig)} */
    ${re.sub(r'^\s*/.*\n', '', i386.pushstr(packing.pack(value), False), 1)}
% else:
    push ${value}
% endif
