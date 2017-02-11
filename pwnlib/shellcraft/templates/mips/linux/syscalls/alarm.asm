
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="seconds"/>
<%docstring>
Invokes the syscall alarm.  See 'man 2 alarm' for more information.

Arguments:
    seconds(unsigned): seconds
</%docstring>

    ${syscall('SYS_alarm', seconds)}
