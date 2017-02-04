
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="clock_id, tp"/>
<%docstring>
Invokes the syscall clock_settime.  See 'man 2 clock_settime' for more information.

Arguments:
    clock_id(clockid_t): clock_id
    tp(timespec): tp
</%docstring>

    ${syscall('SYS_clock_settime', clock_id, tp)}
