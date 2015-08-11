
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="cmd, vararg"/>
<%docstring>
Invokes the syscall ulimit.  See 'man 2 ulimit' for more information.

Arguments:
    cmd(int): cmd
    vararg(int): vararg
</%docstring>

    ${syscall('SYS_ulimit', cmd, vararg)}
