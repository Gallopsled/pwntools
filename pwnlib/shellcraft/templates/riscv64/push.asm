<%
  from pwnlib.shellcraft import riscv64
  from pwnlib import constants
  from pwnlib.shellcraft import registers
  from six import text_type, binary_type
%>
<%page args="value"/>
<%docstring>
Pushes a value onto the stack.

Register t4 is not guaranteed to be preserved.
</%docstring>
<%
is_reg = value in registers.riscv

if not is_reg and isinstance(value, (binary_type, text_type)):
    try:
        value = constants.eval(value)
    except (ValueError, AttributeError):
        pass
%>
% if not is_reg:
    ${riscv64.mov('t4', value)}
    <% value = 't4' %>\
%endif
    sd ${value}, -8(sp)
    addi sp, sp, -8
