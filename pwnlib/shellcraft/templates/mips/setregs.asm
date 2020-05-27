<%
  from pwnlib.regsort import regsort
  from pwnlib.constants import Constant, eval
  from pwnlib.shellcraft import registers
  from pwnlib.shellcraft.mips import mov
%>
<%page args="reg_context, stack_allowed = True"/>
<%docstring>
Sets multiple registers, taking any register dependencies into account
(i.e., given eax=1,ebx=eax, set ebx first).

Args:
    reg_context (dict): Desired register context
    stack_allowed (bool): Can the stack be used?

Example:

    >>> print(shellcraft.setregs({'$t0':1, '$a3':'0'}).rstrip())
        slti $a3, $zero, 0xFFFF /* $a3 = 0 */
        li $t9, ~1
        not $t0, $t9
    >>> print(shellcraft.setregs({'$a0':'$a1', '$a1':'$a0', '$a2':'$a1'}).rstrip())
        sw $a1, -4($sp) /* mov $a2, $a1 */
        lw $a2, -4($sp)
        xor $a1, $a1, $a0 /* xchg $a1, $a0 */
        xor $a0, $a1, $a0
        xor $a1, $a1, $a0
</%docstring>
<%
reg_context = {k:v for k,v in reg_context.items() if v is not None}
sorted_regs = regsort(reg_context, registers.mips)
%>
% if not sorted_regs:
  /* setregs noop */
% else:
% for how, src, dst in regsort(reg_context, registers.mips):
% if how == 'xchg':
    xor ${dst}, ${dst}, ${src} /* xchg ${dst}, ${src} */
    xor ${src}, ${dst}, ${src}
    xor ${dst}, ${dst}, ${src}
% else:
    ${mov(src, dst)}
% endif
% endfor
% endif
