
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="out_fd, in_fd, offset, count"/>
<%docstring>
Invokes the syscall sendfile64.  See 'man 2 sendfile64' for more information.

Arguments:
    out_fd(int): out_fd
    in_fd(int): in_fd
    offset(off64_t): offset
    count(size_t): count
</%docstring>

    ${syscall('SYS_sendfile64', out_fd, in_fd, offset, count)}
