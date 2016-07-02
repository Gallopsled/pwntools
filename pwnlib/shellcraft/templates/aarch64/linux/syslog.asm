
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="pri, fmt, vararg"/>
<%docstring>
Invokes the syscall syslog.  See 'man 2 syslog' for more information.

Arguments:
    pri(int): pri
    fmt(char): fmt
    vararg(int): vararg
</%docstring>

    ${syscall('SYS_syslog', pri, fmt, vararg)}
