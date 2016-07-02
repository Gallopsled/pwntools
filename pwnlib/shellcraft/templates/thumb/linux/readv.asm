
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="fd, iovec, count"/>
<%docstring>
Invokes the syscall readv.  See 'man 2 readv' for more information.

Arguments:
    fd(int): fd
    iovec(iovec): iovec
    count(int): count
</%docstring>

    ${syscall('SYS_readv', fd, iovec, count)}
