
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="pid, cpusetsize, cpuset"/>
<%docstring>
Invokes the syscall sched_setaffinity.  See 'man 2 sched_setaffinity' for more information.

Arguments:
    pid(pid_t): pid
    cpusetsize(size_t): cpusetsize
    cpuset(cpu_set_t): cpuset
</%docstring>

    ${syscall('SYS_sched_setaffinity', pid, cpusetsize, cpuset)}
