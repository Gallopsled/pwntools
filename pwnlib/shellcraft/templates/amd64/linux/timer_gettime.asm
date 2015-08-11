
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="timerid, value"/>
<%docstring>
Invokes the syscall timer_gettime.  See 'man 2 timer_gettime' for more information.

Arguments:
    timerid(timer_t): timerid
    value(itimerspec): value
</%docstring>

    ${syscall('SYS_timer_gettime', timerid, value)}
