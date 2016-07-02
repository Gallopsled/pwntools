
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall getpid.  See 'man 2 getpid' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_getpid')}
