
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="status"/>
<%docstring>
Invokes the syscall exit.  See 'man 2 exit' for more information.

Arguments:
    status(int): status
</%docstring>

    ${syscall('SYS_exit', status)}
