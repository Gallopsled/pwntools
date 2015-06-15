<%
  from pwnlib.regsort import regsort
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
        push 0x1
        pop eax
    >>> print shellcraft.setregs({'eax':'ebx', 'ebx':'eax', 'ecx':'ebx'}).rstrip()
        mov ecx, ebx
        xchg eax, ebx


</%docstring>

% for how, src, dst in regsort(reg_context, registers.i386):
% if how == 'xchg':
    xchg ${src}, ${dst}
% else:
    ${mov(src, dst)}
% endif
% endfor
