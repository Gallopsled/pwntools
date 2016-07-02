<%
  from pwnlib.util import packing
  from pwnlib.shellcraft import mips
  from pwnlib import constants
  from pwnlib.shellcraft import registers
  import re
%>
<%page args="value"/>
<%docstring>
Pushes a value onto the stack.
</%docstring>
<%
value_orig = value
is_reg = value in registers.mips

if not is_reg and isinstance(value, (str, unicode)):
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
