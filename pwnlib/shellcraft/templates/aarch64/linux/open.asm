
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="file, oflag, vararg"/>
<%docstring>
Invokes the syscall open.  See 'man 2 open' for more information.

Arguments:
    file(char): file
    oflag(int): oflag
    vararg(int): vararg
</%docstring>

    ${syscall('SYS_open', file, oflag, vararg)}
