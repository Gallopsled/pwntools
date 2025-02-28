<%
  from pwnlib.shellcraft import loongarch64
  from pwnlib.shellcraft import registers
%>
<%page args="dst,rs1,rs2"/>
<%docstring>
XOR two registers rs1 and rs2, store result in register dst.

Register t4 is not guaranteed to be preserved.
</%docstring>
<%
if not isinstance(dst, str) or dst not in registers.loongarch64:
    log.error("Unknown register %r", dst)
    return
if not isinstance(rs1, str) or rs1 not in registers.loongarch64:
    log.error("Unknown register %r", rs1)
    return
if not isinstance(rs2, str) or rs2 not in registers.loongarch64:
    log.error("Unknown register %r", rs2)
    return

%>
    xor      $${dst}, $${rs1}, $${rs2}
