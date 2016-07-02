<%
    from pwnlib.shellcraft.aarch64.linux import read
    from pwnlib.shellcraft.aarch64 import setregs
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
    ${setregs({'x3': buf, 'x4': nbytes})}
${readn_loop}:
    ${read(fd, 'x3', 'x4')}
    add x3, x3, x0
    subs x4, x4, x0
    bne ${readn_loop}
