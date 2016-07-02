
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall vhangup.  See 'man 2 vhangup' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_vhangup')}
