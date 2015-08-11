
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="fd, buf, nbytes"/>
<%docstring>
Invokes the syscall read.  See 'man 2 read' for more information.

Arguments:
    fd(int): fd
    buf(void): buf
    nbytes(size_t): nbytes
</%docstring>

    ${syscall('SYS_read', fd, buf, nbytes)}
