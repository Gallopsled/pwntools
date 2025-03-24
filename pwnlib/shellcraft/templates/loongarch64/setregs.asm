<%
  from pwnlib.regsort import regsort
  from pwnlib.constants import Constant, eval
  from pwnlib.shellcraft import registers
  from pwnlib.shellcraft import loongarch64
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
        addi.d   $a3, $r0, 0
        addi.d   $t0, $r0, 1
    >>> print(shellcraft.setregs({'a0':'a1', 'a1':'a0', 'a2':'a1'}).rstrip())
        addi.d   $a2, $a1, 0
        xor      $a1, $a1, $a0 /* xchg a1, a0 */
        xor      $a0, $a0, $a1
        xor      $a1, $a1, $a0
</%docstring>
<%
reg_context = {k:v for k,v in reg_context.items() if v is not None}
sorted_regs = regsort(reg_context, registers.loongarch64)
%>
% if sorted_regs:
% for how, src, dst in regsort(reg_context, registers.loongarch64):
% if how == 'xchg':
    ${loongarch64.xor(dst, dst, src)} /* xchg ${dst}, ${src} */
    ${loongarch64.xor(src, src, dst)}
    ${loongarch64.xor(dst, dst, src)}
% else:
    ${loongarch64.mov(src, dst)}
% endif
% endfor
% endif
