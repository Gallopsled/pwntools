
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="fd, buf, n, offset"/>
<%docstring>
Invokes the syscall pwrite.  See 'man 2 pwrite' for more information.

Arguments:
    fd(int): fd
    buf(void): buf
    n(size_t): n
    offset(off_t): offset
</%docstring>

    ${syscall('SYS_pwrite', fd, buf, n, offset)}
