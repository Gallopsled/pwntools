
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="when"/>
<%docstring>
Invokes the syscall stime.  See 'man 2 stime' for more information.

Arguments:
    when(time_t): when
</%docstring>

    ${syscall('SYS_stime', when)}
