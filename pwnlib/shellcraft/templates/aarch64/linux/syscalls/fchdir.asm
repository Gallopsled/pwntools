
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="fd"/>
<%docstring>
Invokes the syscall fchdir.  See 'man 2 fchdir' for more information.

Arguments:
    fd(int): fd
</%docstring>

    ${syscall('SYS_fchdir', fd)}
