<%
  from random import choice
  from pwnlib.shellcraft import registers
%>
<%docstring>Go from ARM to THUMB mode.</%docstring>
<%page args="reg=None, avoid = []"/>
<%
    if reg:
        pass
    elif not avoid or 'r3' not in avoid:
        reg = 'r3'
    else:
        # Avoid registers we don't want to clobber, and r0
        # since it will encode a NULL.
        avoid = set(avoid) | {'r0', 'sp', 'pc', 'cpsr', 'lr'}
        reg   = next(r for r in registers.arm if r not in avoid)
%>
    .arm
    add ${reg}, pc, #1
    bx  ${reg}
    .thumb
