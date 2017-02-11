
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="epfd, op, fd, event"/>
<%docstring>
Invokes the syscall epoll_ctl.  See 'man 2 epoll_ctl' for more information.

Arguments:
    epfd(int): epfd
    op(int): op
    fd(int): fd
    event(epoll_event): event
</%docstring>

    ${syscall('SYS_epoll_ctl', epfd, op, fd, event)}
