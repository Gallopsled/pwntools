
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="pid"/>
<%docstring>
Invokes the syscall sched_getscheduler.  See 'man 2 sched_getscheduler' for more information.

Arguments:
    pid(pid_t): pid
</%docstring>

    ${syscall('SYS_sched_getscheduler', pid)}
