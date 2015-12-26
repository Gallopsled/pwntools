<%
  from pwnlib.regsort import regsort
  from pwnlib.constants import Constant, eval
  from pwnlib.shellcraft import registers
  from pwnlib.shellcraft.aarch64 import mov
%>
<%page args="reg_context, stack_allowed = True"/>
<%docstring>
Sets multiple registers, taking any register dependencies into account
(i.e., given eax=1,ebx=eax, set ebx first).

Args:
    reg_context (dict): Desired register context
    stack_allowed (bool): Can the stack be used?

Example:

    >>> print shellcraft.setregs({'x0':1, 'x2':'x3'}).rstrip()
        mov  x0, #1
        mov  x2, x3
    >>> print shellcraft.setregs({'x0':'x1', 'x1':'x0', 'x2':'x3'}).rstrip()
        mov  x2, x3
        eor  x0, x0, x1 /* xchg x0, x1 */
        eor  x1, x0, x1
        eor  x0, x0, x1
</%docstring>
<%
reg_context = {k:v for k,v in reg_context.items() if v is not None}
sorted_regs = regsort(reg_context, registers.aarch64)
%>
% if not sorted_regs:
  /* setregs noop */
% else:
% for how, dst, src in regsort(reg_context, registers.aarch64):
% if how == 'xchg':
    eor  ${dst}, ${dst}, ${src} /* xchg ${dst}, ${src} */
    eor  ${src}, ${dst}, ${src}
    eor  ${dst}, ${dst}, ${src}
% else:
    ${mov(dst, src)}
% endif
% endfor
% endif
