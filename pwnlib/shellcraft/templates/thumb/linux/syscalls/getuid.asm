
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall getuid.  See 'man 2 getuid' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_getuid')}
