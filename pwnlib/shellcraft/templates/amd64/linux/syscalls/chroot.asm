
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="path"/>
<%docstring>
Invokes the syscall chroot.  See 'man 2 chroot' for more information.

Arguments:
    path(char): path
</%docstring>

    ${syscall('SYS_chroot', path)}
