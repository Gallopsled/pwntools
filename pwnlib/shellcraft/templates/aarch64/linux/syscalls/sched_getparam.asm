
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="pid, param"/>
<%docstring>
Invokes the syscall sched_getparam.  See 'man 2 sched_getparam' for more information.

Arguments:
    pid(pid_t): pid
    param(sched_param): param
</%docstring>

    ${syscall('SYS_sched_getparam', pid, param)}
