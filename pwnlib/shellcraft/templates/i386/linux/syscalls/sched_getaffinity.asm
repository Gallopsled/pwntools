
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="pid, cpusetsize, cpuset"/>
<%docstring>
Invokes the syscall sched_getaffinity.  See 'man 2 sched_getaffinity' for more information.

Arguments:
    pid(pid_t): pid
    cpusetsize(size_t): cpusetsize
    cpuset(cpu_set_t): cpuset
</%docstring>

    ${syscall('SYS_sched_getaffinity', pid, cpusetsize, cpuset)}
