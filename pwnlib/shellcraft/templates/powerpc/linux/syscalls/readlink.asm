
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="path, buf, length"/>
<%docstring>
Invokes the syscall readlink.  See 'man 2 readlink' for more information.

Arguments:
    path(char): path
    buf(char): buf
    len(size_t): len
</%docstring>

    ${syscall('SYS_readlink', path, buf, length)}
