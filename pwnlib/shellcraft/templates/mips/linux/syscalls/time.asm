
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="timer"/>
<%docstring>
Invokes the syscall time.  See 'man 2 time' for more information.

Arguments:
    timer(time_t): timer
</%docstring>

    ${syscall('SYS_time', timer)}
