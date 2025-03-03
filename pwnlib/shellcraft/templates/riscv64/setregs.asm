<%
  from pwnlib.regsort import regsort
  from pwnlib.constants import Constant, eval
  from pwnlib.shellcraft import registers
  from pwnlib.shellcraft import riscv64
%>
<%page args="reg_context, stack_allowed = True"/>
<%docstring>
Sets multiple registers, taking any register dependencies into account
(i.e., given eax=1,ebx=eax, set ebx first).

Args:
    reg_context (dict): Desired register context
    stack_allowed (bool): Can the stack be used?

Example:

    >>> print(shellcraft.setregs({'t0':1, 'a3':'0'}).rstrip())
        c.li a3, 0
        c.li t0, 1
    >>> print(shellcraft.setregs({'a0':'a1', 'a1':'a0', 'a2':'a1'}).rstrip())
        c.mv a2, a1
        c.mv t4, a1
        xor a1, a0, t4 /* xchg a1, a0 */
        c.mv t4, a0
        xor a0, a1, t4
        c.mv t4, a1
        xor a1, a0, t4
</%docstring>
<%
reg_context = {k:v for k,v in reg_context.items() if v is not None}
sorted_regs = regsort(reg_context, registers.riscv)
%>
% if not sorted_regs:
  /* setregs noop */
% else:
% for how, src, dst in regsort(reg_context, registers.riscv):
% if how == 'xchg':
    ${riscv64.xor(dst, dst, src)} /* xchg ${dst}, ${src} */
    ${riscv64.xor(src, src, dst)}
    ${riscv64.xor(dst, dst, src)}
% else:
    ${riscv64.mov(src, dst)}
% endif
% endfor
% endif
