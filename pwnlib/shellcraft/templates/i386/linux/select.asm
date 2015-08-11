
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="nfds, readfds, writefds, exceptfds, timeout"/>
<%docstring>
Invokes the syscall select.  See 'man 2 select' for more information.

Arguments:
    nfds(int): nfds
    readfds(fd_set): readfds
    writefds(fd_set): writefds
    exceptfds(fd_set): exceptfds
    timeout(timeval): timeout
</%docstring>

    ${syscall('SYS_select', nfds, readfds, writefds, exceptfds, timeout)}
