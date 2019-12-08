<%
  from pwnlib.util import packing
  from pwnlib.shellcraft import mips
  from pwnlib import constants
  from pwnlib.shellcraft import registers
  from six import text_type, binary_type
  import re
%>
<%page args="value"/>
<%docstring>
Pushes a value onto the stack.
</%docstring>
<%
value_orig = value
is_reg = value in registers.mips

if not is_reg and isinstance(value, (binary_type, text_type)):
    try:
        value = constants.eval(value)
    except (ValueError, AttributeError):
        pass
%>
% if not is_reg:
    ${mips.mov('$t0', value)}
    <% value = '$t0' %>\
%endif
    sw ${value}, -4($sp)
    addi $sp, $sp, -4
