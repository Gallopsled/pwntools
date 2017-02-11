
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="which, new, old"/>
<%docstring>
Invokes the syscall setitimer.  See 'man 2 setitimer' for more information.

Arguments:
    which(itimer_which_t): which
    new(itimerval): new
    old(itimerval): old
</%docstring>

    ${syscall('SYS_setitimer', which, new, old)}
