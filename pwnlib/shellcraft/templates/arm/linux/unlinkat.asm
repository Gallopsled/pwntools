
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fd, name, flag"/>
<%docstring>
Invokes the syscall unlinkat.  See 'man 2 unlinkat' for more information.

Arguments:
    fd(int): fd
    name(char): name
    flag(int): flag
</%docstring>

    ${syscall('SYS_unlinkat', fd, name, flag)}
