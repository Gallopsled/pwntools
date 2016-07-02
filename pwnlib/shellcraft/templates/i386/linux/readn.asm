<%
    from pwnlib.shellcraft.i386.linux import read
    from pwnlib.shellcraft.i386 import setregs
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
    ${setregs({'ecx': buf, 'edx': nbytes})}
${readn_loop}:
    ${read(fd, 'ecx', 'edx')}
    add ecx, eax
    sub edx, eax
    jnz ${readn_loop}
