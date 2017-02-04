
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="fd, buf, nbytes, offset"/>
<%docstring>
Invokes the syscall pread.  See 'man 2 pread' for more information.

Arguments:
    fd(int): fd
    buf(void): buf
    nbytes(size_t): nbytes
    offset(off_t): offset
</%docstring>

    ${syscall('SYS_pread', fd, buf, nbytes, offset)}
