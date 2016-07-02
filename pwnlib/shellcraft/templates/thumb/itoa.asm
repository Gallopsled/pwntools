<%
from pwnlib.shellcraft import pretty, value, common, registers
from pwnlib.shellcraft.thumb import mov, pushstr, udiv_10, setregs
from pwnlib import constants
%>
<%docstring>
Converts an integer into its string representation, and pushes it
onto the stack.  Uses registers r0-r5.

Arguments:
    v(str, int):
        Integer constant or register that contains the value to convert.
    alloca

Example:

    >>> sc = shellcraft.thumb.mov('r0', 0xdeadbeef)
    >>> sc += shellcraft.thumb.itoa('r0')
    >>> sc += shellcraft.thumb.linux.write(1, 'sp', 32)
    >>> run_assembly(sc).recvuntil('\x00')
    '3735928559\x00'
</%docstring>
<%page args="v, buffer='sp', allocate_stack=True"/>
<%
itoa_loop = common.label('itoa_loop')
size_loop = common.label('size_loop')
one_char  = common.label('one_char')
assert v in registers.thumb
%>\
    /* atoi(${pretty(v,0)}) */
%if allocate_stack and buffer=='sp':
    sub sp, sp, 0x10
%endif
## REGISTER USAGE
##
## r0: Value (also used in udiv_10)
## r1: Used in udiv_10
## r2: Used in udiv_10
## r3: Length of string, current character
## r4: Buffer pointer
## r5: Remainder
    ${setregs({'r0': v,
               'r3': 0,
               'r4': buffer})}
## Save for later
    push {r0}
## Calculate how many characters are needed.
## e.g.    0 -> 1
##         1 -> 1
##        23 -> 2
##      1234 -> 4
${size_loop}:
    add r3, r3, 1
    ${udiv_10('r0')}
    cmp r0, 1
    bhs ${size_loop}
## Calculate the end of the buffer and null-terminate
## N.B. r0 == 0 here
    add r3, r4, r3
    strb r0, [r3, #1]
## Grab saved "original value" off the stack
    pop {r0}
${itoa_loop}:
    ${mov('r5', 'r0')}  /* save before division */
    ${udiv_10('r0')}
## Multiply back by 10 to get remainder
    /* multiply by 10 to get remainder in r5 */
    ${mov('r1', 10)}
    umull r1, r2, r0, r1
    sub r5, r5, r1
    /* store the byte, decrement, check complete */
    add r5, r5, ${ord('0')}
    strb r5, [r3, #-1]!
    cmp r3, r4
    bgt ${itoa_loop}
