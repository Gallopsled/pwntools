
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="epfd, events, maxevents, timeout"/>
<%docstring>
Invokes the syscall epoll_wait.  See 'man 2 epoll_wait' for more information.

Arguments:
    epfd(int): epfd
    events(epoll_event): events
    maxevents(int): maxevents
    timeout(int): timeout
</%docstring>

    ${syscall('SYS_epoll_wait', epfd, events, maxevents, timeout)}
