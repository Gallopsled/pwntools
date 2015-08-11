<%
  from pwnlib.regsort import regsort
  from pwnlib.constants import Constant, eval
  from pwnlib.shellcraft import registers
  from pwnlib.shellcraft.i386 import mov
%>
<%page args="reg_context, stack_allowed = True"/>
<%docstring>
Sets multiple registers, taking any register dependencies into account
(i.e., given eax=1,ebx=eax, set ebx first).

Args:
    reg_context (dict): Desired register context
    stack_allowed (bool): Can the stack be used?

Example:

    >>> print shellcraft.setregs({'eax':1, 'ebx':'eax'}).rstrip()
        mov ebx, eax
        push 1
        pop eax
    >>> print shellcraft.setregs({'eax':'ebx', 'ebx':'eax', 'ecx':'ebx'}).rstrip()
        mov ecx, ebx
        xchg eax, ebx


</%docstring>
<%
reg_context = {k:v for k,v in reg_context.items() if v is not None}

eax = reg_context.get('eax', None)
edx = reg_context.get('edx', None)
cdq = False

if isinstance(eax, str):
    try:
        eax = eval(eax)
    except NameError:
        pass

if isinstance(edx, str):
    try:
        edx = eval(edx)
    except NameError:
        pass

if isinstance(eax, int) and isinstance(edx, int) and eax >> 31 == edx:
    cdq = True
    reg_context.pop('edx')

sorted_regs = regsort(reg_context, registers.i386)
%>
% if not sorted_regs:
  /* setregs noop */
% else:
% for how, src, dst in regsort(reg_context, registers.i386):
% if how == 'xchg':
    xchg ${src}, ${dst}
% else:
    ${mov(src, dst)}
% endif
% endfor
% if cdq:
    cdq /* edx=0 */
% endif
% endif
