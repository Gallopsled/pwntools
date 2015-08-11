<%
  from pwnlib.regsort import regsort
  from pwnlib.constants import Constant, eval
  from pwnlib.shellcraft import registers
  from pwnlib.shellcraft.thumb import mov
%>
<%page args="reg_context, stack_allowed = True"/>
<%docstring>
Sets multiple registers, taking any register dependencies into account
(i.e., given eax=1,ebx=eax, set ebx first).

Args:
    reg_context (dict): Desired register context
    stack_allowed (bool): Can the stack be used?

Example:

    >>> print shellcraft.setregs({'r0':1, 'r2':'r3'}).rstrip()
        mov r0, #1
        mov r2, r3
    >>> print shellcraft.setregs({'r0':'r1', 'r1':'r0', 'r2':'r3'}).rstrip()
        mov r2, r3
        eor r0, r0, r1 /* xchg r0, r1 */
        eor r1, r0, r1
        eor r0, r0, r1
</%docstring>
<%
reg_context = {k:v for k,v in reg_context.items() if v is not None}
sorted_regs = regsort(reg_context, registers.arm)
%>
% if not sorted_regs:
  /* setregs noop */
% else:
% for how, dst, src in regsort(reg_context, registers.arm):
% if how == 'xchg':
    eor ${dst}, ${dst}, ${src} /* xchg ${dst}, ${src} */
    eor ${src}, ${dst}, ${src}
    eor ${dst}, ${dst}, ${src}
% else:
    ${mov(dst, src)}
% endif
% endfor
% endif
