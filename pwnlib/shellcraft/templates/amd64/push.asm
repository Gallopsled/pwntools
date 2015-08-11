<%
  from pwnlib.util import packing
  from pwnlib.shellcraft import amd64
  from pwnlib.shellcraft.amd64 import pushstr
  from pwnlib import constants
  from pwnlib.shellcraft.registers import amd64 as regs
  from pwnlib.context import context as ctx # Ugly hack, mako will not let it be called context
  import re
%>
<%page args="value"/>
<%docstring>
Pushes a value onto the stack without using
null bytes or newline characters.

If src is a string, then we try to evaluate with `context.arch = 'amd64'` using
:func:`pwnlib.constants.eval` before determining how to push it. Note that this
means that this shellcode can change behavior depending on the value of
`context.os`.

Args:
  value (int,str): The value or register to push

Example:

    >>> print pwnlib.shellcraft.amd64.push(0).rstrip()
        /* push 0 */
        push 1
        dec byte ptr [rsp]
    >>> print pwnlib.shellcraft.amd64.push(1).rstrip()
        /* push 1 */
        push 1
    >>> print pwnlib.shellcraft.amd64.push(256).rstrip()
        /* push 256 */
        push 0x1010201 ^ 0x100
        xor dword ptr [rsp], 0x1010201
    >>> with context.local(os = 'linux'):
    ...     print pwnlib.shellcraft.amd64.push('SYS_write').rstrip()
        /* push 'SYS_write' */
        push 1
    >>> with context.local(os = 'freebsd'):
    ...     print pwnlib.shellcraft.amd64.push('SYS_write').rstrip()
        /* push 'SYS_write' */
        push 4

</%docstring>

<%
  value_orig = value
  is_reg = False
  if value in regs:
    is_reg = True
  if not is_reg and isinstance(value, (str, unicode)):
    try:
      with ctx.local(arch = 'amd64'):
        value = constants.eval(value)
    except (ValueError, AttributeError):
        pass
%>
%if not is_reg:
    /* push ${repr(value_orig)} */
    ${re.sub(r'^\s*/.*\n', '', amd64.pushstr(packing.pack(value), False), 1)}
% else:
    push ${value}
% endif

