
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="fd, path, buf, length"/>
<%docstring>
Invokes the syscall readlinkat.  See 'man 2 readlinkat' for more information.

Arguments:
    fd(int): fd
    path(char): path
    buf(char): buf
    len(size_t): len
</%docstring>

    ${syscall('SYS_readlinkat', fd, path, buf, length)}
