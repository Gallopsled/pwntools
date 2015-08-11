
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="clock_id, res"/>
<%docstring>
Invokes the syscall clock_getres.  See 'man 2 clock_getres' for more information.

Arguments:
    clock_id(clockid_t): clock_id
    res(timespec): res
</%docstring>

    ${syscall('SYS_clock_getres', clock_id, res)}
