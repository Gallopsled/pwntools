
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="fd, buf, n, flags"/>
<%docstring>
Invokes the syscall recv.  See 'man 2 recv' for more information.

Arguments:
    fd(int): fd
    buf(void): buf
    n(size_t): n
    flags(int): flags
</%docstring>

    ${syscall('SYS_recv', fd, buf, n, flags)}
