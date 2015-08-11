
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="which, value"/>
<%docstring>
Invokes the syscall getitimer.  See 'man 2 getitimer' for more information.

Arguments:
    which(itimer_which_t): which
    value(itimerval): value
</%docstring>

    ${syscall('SYS_getitimer', which, value)}
