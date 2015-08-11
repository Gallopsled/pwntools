
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fd, iovec, count"/>
<%docstring>
Invokes the syscall writev.  See 'man 2 writev' for more information.

Arguments:
    fd(int): fd
    iovec(iovec): iovec
    count(int): count
</%docstring>

    ${syscall('SYS_writev', fd, iovec, count)}
