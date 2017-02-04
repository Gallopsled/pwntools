
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="pid, stat_loc, options, usage"/>
<%docstring>
Invokes the syscall wait4.  See 'man 2 wait4' for more information.

Arguments:
    pid(pid_t): pid
    stat_loc(WAIT_STATUS): stat_loc
    options(int): options
    usage(rusage): usage
</%docstring>

    ${syscall('SYS_wait4', pid, stat_loc, options, usage)}
