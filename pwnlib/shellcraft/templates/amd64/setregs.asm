<%
  from pwnlib.regsort import regsort
  from pwnlib.shellcraft import registers
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

    >>> print shellcraft.setregs({'rax':1, 'rbx':'rax'}).rstrip()
        mov rbx, rax
        push 0x1
        pop rax
    >>> print shellcraft.setregs({'rax':'rbx', 'rbx':'rax', 'rcx':'rbx'}).rstrip()
        mov rcx, rbx
        xchg rax, rbx

</%docstring>

% for how, src, dst in regsort(reg_context, registers.amd64):
% if how == 'xchg':
    xchg ${src}, ${dst}
% else:
    ${mov(src, dst)}
% endif
% endfor
