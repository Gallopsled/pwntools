
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall setsid.  See 'man 2 setsid' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_setsid')}
