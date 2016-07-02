
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="flags"/>
<%docstring>
Invokes the syscall mlockall.  See 'man 2 mlockall' for more information.

Arguments:
    flags(int): flags
</%docstring>

    ${syscall('SYS_mlockall', flags)}
