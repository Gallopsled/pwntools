<%
  from pwnlib.shellcraft import common
  from pwnlib.shellcraft import arm
%>
<%page args="N"/>
<%docstring>
Divides r0 by 10.  Result is stored in r0, N and Z flags are updated.

Code is from generated from here:
    https://raw.githubusercontent.com/rofirrim/raspberry-pi-assembler/master/chapter15/magic.py

With code:
    python magic.py 10 code_for_unsigned
</%docstring>
    /* r0 = ${N} / 10 */
    ${arm.setregs({'r0': N, 'r1': 0xcccccccd})}
    umull r1, r2, r0, r1   /* r1 <- Lower32Bits(r1*r0). r2 <- Upper32Bits(r1*r0) */
    movs r0, r2, LSR #3     /* r0 <- r2 >> 3 */
