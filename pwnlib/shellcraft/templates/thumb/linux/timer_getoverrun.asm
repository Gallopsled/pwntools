
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="timerid"/>
<%docstring>
Invokes the syscall timer_getoverrun.  See 'man 2 timer_getoverrun' for more information.

Arguments:
    timerid(timer_t): timerid
</%docstring>

    ${syscall('SYS_timer_getoverrun', timerid)}
