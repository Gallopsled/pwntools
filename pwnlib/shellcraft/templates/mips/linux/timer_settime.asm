
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="timerid, flags, value, ovalue"/>
<%docstring>
Invokes the syscall timer_settime.  See 'man 2 timer_settime' for more information.

Arguments:
    timerid(timer_t): timerid
    flags(int): flags
    value(itimerspec): value
    ovalue(itimerspec): ovalue
</%docstring>

    ${syscall('SYS_timer_settime', timerid, flags, value, ovalue)}
