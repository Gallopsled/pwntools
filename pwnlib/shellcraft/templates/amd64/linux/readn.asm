<%
    from pwnlib.shellcraft.amd64.linux import read
    from pwnlib.shellcraft.amd64 import setregs
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
    ${setregs({'rsi': buf, 'rdx': nbytes})}
${readn_loop}:
    ${read(fd, 'rsi', 'rdx')}
    add rsi, rax
    sub rdx, rax
    jnz ${readn_loop}
