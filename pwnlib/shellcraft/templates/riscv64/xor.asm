<%
  from pwnlib.shellcraft import riscv64
  from pwnlib.shellcraft import registers
%>
<%page args="dst,rs1,rs2"/>
<%docstring>
XOR two registers rs1 and rs2, store result in register dst.

Register t4 is not guaranteed to be preserved.
</%docstring>
<%
if not isinstance(dst, str) or dst not in registers.riscv:
    log.error("Unknown register %r", dst)
    return
if not isinstance(rs1, str) or rs1 not in registers.riscv:
    log.error("Unknown register %r", rs1)
    return
if not isinstance(rs2, str) or rs2 not in registers.riscv:
    log.error("Unknown register %r", rs2)
    return

rs1_reg = registers.riscv[rs1]
rs2_reg = registers.riscv[rs2]
%>

##  always safe
## c.xor rs1d  rs2
## 100011dd d01sss01

## xor      rs2  rs1      rd
## 0000000s ssssSSSS S100ddddd 0110011
% if rs2_reg & 0x10 and (rs1_reg >> 1 | ((rs2_reg & 0xf) << 4)) not in (0, 10):
    xor ${dst}, ${rs1}, ${rs2}
% elif rs1_reg & 0x10 and (rs2_reg >> 1 | ((rs1_reg & 0xf) << 4)) not in (0, 10):
    xor ${dst}, ${rs2}, ${rs1}
% else:
    ${riscv64.mov('t4', rs1)}
    xor ${dst}, ${rs2}, t4
% endif
