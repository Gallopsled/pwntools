<%
  import six
  from pwnlib.regsort import regsort
  from pwnlib.shellcraft import registers, eval
  from pwnlib.shellcraft.amd64 import mov
%>
<%page args="reg_context, stack_allowed = True"/>
<%docstring>
Sets multiple registers, taking any register dependencies into account
(i.e., given eax=1,ebx=eax, set ebx first).

Args:
    reg_context (dict): Desired register context
    stack_allowed (bool): Can the stack be used?

Example:

    >>> print(shellcraft.setregs({'rax':1, 'rbx':'rax'}).rstrip())
        mov rbx, rax
        push 1
        pop rax
    >>> print(shellcraft.setregs({'rax': 'SYS_write', 'rbx':'rax'}).rstrip())
        mov rbx, rax
        push SYS_write /* 1 */
        pop rax
    >>> print(shellcraft.setregs({'rax':'rbx', 'rbx':'rax', 'rcx':'rbx'}).rstrip())
        mov rcx, rbx
        xchg rax, rbx
    >>> print(shellcraft.setregs({'rax':1, 'rdx':0}).rstrip())
        push 1
        pop rax
        cdq /* rdx=0 */

</%docstring>
<%
reg_context = {k:v for k,v in reg_context.items() if v is not None}

eax = reg_context.get('rax', None)
edx = reg_context.get('rdx', None)
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

if isinstance(eax, six.integer_types) and isinstance(edx, six.integer_types) and eax >> 63 == edx:
    cdq = True
    reg_context.pop('rdx')

sorted_regs = regsort(reg_context, registers.amd64)
%>
% if not sorted_regs:
  /* setregs noop */
% else:
% for how, src, dst in sorted_regs:
% if how == 'xchg':
    xchg ${src}, ${dst}
% else:
    ${mov(src, dst)}
% endif
% endfor
% if cdq:
    cdq /* rdx=0 */
% endif
% endif
