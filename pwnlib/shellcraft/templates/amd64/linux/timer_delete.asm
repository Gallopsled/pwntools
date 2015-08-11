
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="timerid"/>
<%docstring>
Invokes the syscall timer_delete.  See 'man 2 timer_delete' for more information.

Arguments:
    timerid(timer_t): timerid
</%docstring>

    ${syscall('SYS_timer_delete', timerid)}
