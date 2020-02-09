<% from pwnlib.shellcraft.mips import mov, nop %>
<% from socket import htons %>
<%page args="port = None"/>
<%docstring>
    findpeer(port)

    Finds a connected socket. If port is specified it is checked
    against the peer port. Resulting socket is left in $s0.
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
    .set noat
    ${mov('$at', 1)}
    add $s0, $s0, $at

    /* First argument is file descriptor */
    ${mov('$a0', '$s0')}

    /* Second argument is pointer to where to store inet addr */
    add $a1, $sp, -16

    /* Third argument is pointer to size */
    add $a2, $sp, -20
    ${mov('$at', 16)}
    sw $at, -20($sp)
    
    ${mov('$v0', 'SYS_getpeername')}
    syscall 0x42424

    bne $v0, $zero, next_socket
    /* Have a nop */
    ${nop()}
% if not port is None:

compare_port:
    /* Read port number into $t0 */
    lhu $t0, -14($sp)
    /* Port to search for into $at */
    ${mov('$at', port)}
    bne $t0, $at, next_socket
% endif
