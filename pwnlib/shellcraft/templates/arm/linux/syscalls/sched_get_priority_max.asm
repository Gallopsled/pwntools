
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="algorithm"/>
<%docstring>
Invokes the syscall sched_get_priority_max.  See 'man 2 sched_get_priority_max' for more information.

Arguments:
    algorithm(int): algorithm
</%docstring>

    ${syscall('SYS_sched_get_priority_max', algorithm)}
