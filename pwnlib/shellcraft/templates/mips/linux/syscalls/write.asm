
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="fd, buf, n"/>
<%docstring>
Invokes the syscall write.  See 'man 2 write' for more information.

Arguments:
    fd(int): fd
    buf(void): buf
    n(size_t): n
</%docstring>

    ${syscall('SYS_write', fd, buf, n)}
