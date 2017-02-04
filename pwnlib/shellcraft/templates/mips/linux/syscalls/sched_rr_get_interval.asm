
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="pid, t"/>
<%docstring>
Invokes the syscall sched_rr_get_interval.  See 'man 2 sched_rr_get_interval' for more information.

Arguments:
    pid(pid_t): pid
    t(timespec): t
</%docstring>

    ${syscall('SYS_sched_rr_get_interval', pid, t)}
