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
<%

# If None is passed in for register values, disregard it
reg_context = {k:v for k,v in reg_context.items() if v is not None}

# If EAX is known to be positive and EDX is zero,
# we can cheat slightly and use 'cdq'

eax = reg_context.get('eax', None)
edx = reg_context.get('edx', None)
cdq = False

if None not in (eax,edx) and eax > 0 and edx == 0:
    reg_context.pop('edx')
    cdq = True

%>

% for how, src, dst in regsort(reg_context, registers.i386):
% if how == 'xchg':
    xchg ${src}, ${dst}
% else:
    ${mov(src, dst)}
% endif
% endfor
% if cdq:
    cdq /* Set edx to 0, eax is known to be positive */
% endif
