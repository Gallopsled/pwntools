<%
  from pwnlib.util import packing
  from pwnlib.shellcraft import i386
  from pwnlib import constants
  from pwnlib.shellcraft.registers import get_register, is_register, bits_required
  from six import text_type
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

    >>> print(pwnlib.shellcraft.i386.push(0).rstrip())
        /* push 0 */
        push 1
        dec byte ptr [esp]
    >>> print(pwnlib.shellcraft.i386.push(1).rstrip())
        /* push 1 */
        push 1
    >>> print(pwnlib.shellcraft.i386.push(256).rstrip())
        /* push 0x100 */
        push 0x1010201
        xor dword ptr [esp], 0x1010301
    >>> print(pwnlib.shellcraft.i386.push('SYS_execve').rstrip())
        /* push SYS_execve (0xb) */
        push 0xb
    >>> print(pwnlib.shellcraft.i386.push('SYS_sendfile').rstrip())
        /* push SYS_sendfile (0xbb) */
        push 0x1010101
        xor dword ptr [esp], 0x10101ba
    >>> with context.local(os = 'freebsd'):
    ...     print(pwnlib.shellcraft.i386.push('SYS_execve').rstrip())
        /* push SYS_execve (0x3b) */
        push 0x3b
</%docstring>

<%
value_orig = value
is_reg = get_register(value)

if not is_reg and isinstance(value, (str, text_type)):
    try:
        value = constants.eval(value)
    except (ValueError, AttributeError):
        pass
%>

% if is_reg:
    push ${value}
% else:
    ${i386.pushstr(value, False)}
% endif
