
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="clock_id, flags, req, rem"/>
<%docstring>
Invokes the syscall clock_nanosleep.  See 'man 2 clock_nanosleep' for more information.

Arguments:
    clock_id(clockid_t): clock_id
    flags(int): flags
    req(timespec): req
    rem(timespec): rem
</%docstring>

    ${syscall('SYS_clock_nanosleep', clock_id, flags, req, rem)}
