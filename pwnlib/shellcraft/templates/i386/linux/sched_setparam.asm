
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="pid, param"/>
<%docstring>
Invokes the syscall sched_setparam.  See 'man 2 sched_setparam' for more information.

Arguments:
    pid(pid_t): pid
    param(sched_param): param
</%docstring>

    ${syscall('SYS_sched_setparam', pid, param)}
