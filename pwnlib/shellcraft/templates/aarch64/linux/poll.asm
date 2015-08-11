
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="fds, nfds, timeout"/>
<%docstring>
Invokes the syscall poll.  See 'man 2 poll' for more information.

Arguments:
    fds(pollfd): fds
    nfds(nfds_t): nfds
    timeout(int): timeout
</%docstring>

    ${syscall('SYS_poll', fds, nfds, timeout)}
