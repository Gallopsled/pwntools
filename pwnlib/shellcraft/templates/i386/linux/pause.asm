
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall pause.  See 'man 2 pause' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_pause')}
