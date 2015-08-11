
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall sched_yield.  See 'man 2 sched_yield' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_sched_yield')}
