
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall sync.  See 'man 2 sync' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_sync')}
