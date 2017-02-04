
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="clock_id, tp"/>
<%docstring>
Invokes the syscall clock_gettime.  See 'man 2 clock_gettime' for more information.

Arguments:
    clock_id(clockid_t): clock_id
    tp(timespec): tp
</%docstring>

    ${syscall('SYS_clock_gettime', clock_id, tp)}
