
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall vfork.  See 'man 2 vfork' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_vfork')}
