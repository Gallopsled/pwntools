<%
  from pwnlib.util import packing
  from pwnlib.shellcraft import thumb
  from pwnlib import constants
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  import re
%>
<%page args="value"/>
<%docstring>
Pushes a value onto the stack without using
null bytes or newline characters.

If src is a string, then we try to evaluate with `context.arch = 'thumb'` using
:func:`pwnlib.constants.eval` before determining how to push it. Note that this
means that this shellcode can change behavior depending on the value of
`context.os`.

Args:
  value (int,str): The value or register to push

Example:

    >>> print pwnlib.shellcraft.thumb.push(0).rstrip()
        /* push 0 */
        eor r1, r1
        push {r1}
    >>> print pwnlib.shellcraft.thumb.push(1).rstrip()
        /* push 1 */
        mov r1, #1
        push {r1}
    >>> print pwnlib.shellcraft.thumb.push(256).rstrip()
        /* push 256 */
        mov r1, #1
        lsl r1, #8
        push {r1}
    >>> with context.local(os = 'linux'):
    ...     print pwnlib.shellcraft.thumb.push('SYS_execve').rstrip()
        /* push 'SYS_execve' */
        mov r1, #11
        push {r1}
    >>> with context.local(os = 'freebsd'):
    ...     print pwnlib.shellcraft.thumb.push('SYS_execve').rstrip()
        /* push 'SYS_execve' */
        mov r1, #59
        push {r1}
</%docstring>

<%
  value_orig = value
  if isinstance(value, (str, unicode)):
    try:
      with ctx.local(arch = 'thumb'):
        value = constants.eval(value)
    except (ValueError, AttributeError):
      pass
%>

% if isinstance(value, (int,long)):
    /* push ${repr(value_orig)} */
    ${re.sub(r'^\s*/.*\n', '', thumb.pushstr(packing.pack(value), False), 1)}
% else:
    push ${value}
% endif
