
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="pid, policy, param"/>
<%docstring>
Invokes the syscall sched_setscheduler.  See 'man 2 sched_setscheduler' for more information.

Arguments:
    pid(pid_t): pid
    policy(int): policy
    param(sched_param): param
</%docstring>

    ${syscall('SYS_sched_setscheduler', pid, policy, param)}
