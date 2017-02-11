
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="clock_id, evp, timerid"/>
<%docstring>
Invokes the syscall timer_create.  See 'man 2 timer_create' for more information.

Arguments:
    clock_id(clockid_t): clock_id
    evp(sigevent): evp
    timerid(timer_t): timerid
</%docstring>

    ${syscall('SYS_timer_create', clock_id, evp, timerid)}
