
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fds, nfds, timeout, ss"/>
<%docstring>
Invokes the syscall ppoll.  See 'man 2 ppoll' for more information.

Arguments:
    fds(pollfd): fds
    nfds(nfds_t): nfds
    timeout(timespec): timeout
    ss(sigset_t): ss
</%docstring>

    ${syscall('SYS_ppoll', fds, nfds, timeout, ss)}
