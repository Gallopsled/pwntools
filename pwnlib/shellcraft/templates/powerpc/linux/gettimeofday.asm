
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="tv, tz"/>
<%docstring>
Invokes the syscall gettimeofday.  See 'man 2 gettimeofday' for more information.

Arguments:
    tv(timeval): tv
    tz(timezone_ptr_t): tz
</%docstring>

    ${syscall('SYS_gettimeofday', tv, tz)}
