
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall munlockall.  See 'man 2 munlockall' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_munlockall')}
