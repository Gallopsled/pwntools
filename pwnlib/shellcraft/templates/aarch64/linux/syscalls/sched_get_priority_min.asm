
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="algorithm"/>
<%docstring>
Invokes the syscall sched_get_priority_min.  See 'man 2 sched_get_priority_min' for more information.

Arguments:
    algorithm(int): algorithm
</%docstring>

    ${syscall('SYS_sched_get_priority_min', algorithm)}
