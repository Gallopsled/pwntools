
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="tv, tz"/>
<%docstring>
Invokes the syscall settimeofday.  See 'man 2 settimeofday' for more information.

Arguments:
    tv(timeval): tv
    tz(timezone): tz
</%docstring>

    ${syscall('SYS_settimeofday', tv, tz)}
