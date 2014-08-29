<% from pwnlib.shellcraft.thumb import mov %>
<% from pwnlib import constants %>
<% from socket import htons %>
<%page args="port = None"/>
<%docstring>
    findpeer(port)

    Finds a connected socket. If port is specified it is checked
    against the peer port. Resulting socket is left in r6.
</%docstring>
findpeer:
    /* File descriptor in r6 */
    /* Inside the loop we begin by incrementing it */
    /* so initially we want it to be -1 */
    ${mov('r6', -1)}
    /* Let us restore stack easily */
    mov lr, sp

next_socket:
    /* Next file descriptor */
    add r6, #1

    ${mov('r7', constants.linux.thumb.SYS_getpeername)}

    /* Reset stack */
    mov sp, lr

    /* First argument is file descriptor */
    mov r0, r6

    /* Make room on stack - inet addr structure is 16 bytes and size of addr is four bytes */
    /* First four bytes will be the size of the address, the remaining 16 bytes will be */
    /* the address structure */
    push {r0, r1, r2, r3, r4}

    /* Second argument is pointer to where to store inet addr */
    add r1, sp, #4

    /* Third argument is pointer to size */
    mov r2, sp

    /* Now issue system call */
    svc 1

    /* If the syscall returned -1 this was a bad socket */
    /* so move on to the next one */
    /* Testing on r0 has nul bytes but moving to r1 achieves the same */
    cmp r0, #0
    bne next_socket
%if not port is None:

compare_port:
    /* Read the port into r0 */
    ldr r1, [sp, #4]
    lsr r1, #16

    /* Put the port (${port}) to search for into r1 */
    ${mov('r2', htons(int(port)))}

    /* Is it the one we have been searching for? */
    cmp r1, r2
    
    /* If not try the next one */
    bne next_socket
%endif
