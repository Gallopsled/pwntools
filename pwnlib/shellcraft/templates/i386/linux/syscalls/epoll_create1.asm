
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="flags"/>
<%docstring>
Invokes the syscall epoll_create1.  See 'man 2 epoll_create1' for more information.

Arguments:
    flags(int): flags
</%docstring>

    ${syscall('SYS_epoll_create1', flags)}
