
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="epfd, events, maxevents, timeout, ss"/>
<%docstring>
Invokes the syscall epoll_pwait.  See 'man 2 epoll_pwait' for more information.

Arguments:
    epfd(int): epfd
    events(epoll_event): events
    maxevents(int): maxevents
    timeout(int): timeout
    ss(sigset_t): ss
</%docstring>

    ${syscall('SYS_epoll_pwait', epfd, events, maxevents, timeout, ss)}
