<%
  from pwnlib.shellcraft import loongarch64
  from pwnlib import constants
  from pwnlib.shellcraft import registers
%>
<%page args="value"/>
<%docstring>
Pushes a value onto the stack.

Register t8 is not guaranteed to be preserved.
</%docstring>
<%
is_reg = value in registers.loongarch64

if not is_reg and isinstance(value, (bytes, str)):
    try:
        value = constants.eval(value)
    except (ValueError, AttributeError):
        pass
%>
% if not is_reg:
    ${loongarch64.mov('t8', value)}
    <% value = 't8' %>\
%endif
    addi.d   $sp, $sp, -8
    st.d     $${value}, $sp, 0
