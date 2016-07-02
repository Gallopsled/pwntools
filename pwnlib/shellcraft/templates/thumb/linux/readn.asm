<%
    from pwnlib.shellcraft.thumb.linux import read
    from pwnlib.shellcraft.thumb import setregs
    from pwnlib.shellcraft import common
%>
<%page args="fd, buf, nbytes"/>
<%docstring>
Reads exactly nbytes bytes from file descriptor fd into the buffer buf.

Arguments:
    fd(int): fd
    buf(void): buf
    nbytes(size_t): nbytes
</%docstring>
<%
readn_loop = common.label('readn_loop')
%>
    ${setregs({'r3': buf, 'r4': nbytes})}
${readn_loop}:
    ${read(fd, 'r3', 'r4')}
    add r3, r3, r0
    subs r4, r4, r0
    bne ${readn_loop}
