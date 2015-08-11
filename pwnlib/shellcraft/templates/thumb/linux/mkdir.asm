
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="path, mode"/>
<%docstring>
Invokes the syscall mkdir.  See 'man 2 mkdir' for more information.

Arguments:
    path(char): path
    mode(mode_t): mode
</%docstring>

    ${syscall('SYS_mkdir', path, mode)}
