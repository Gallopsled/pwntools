
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall getegid.  See 'man 2 getegid' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_getegid')}
