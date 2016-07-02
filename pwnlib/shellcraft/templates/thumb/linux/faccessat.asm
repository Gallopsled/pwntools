
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="fd, file, type, flag"/>
<%docstring>
Invokes the syscall faccessat.  See 'man 2 faccessat' for more information.

Arguments:
    fd(int): fd
    file(char): file
    type(int): type
    flag(int): flag
</%docstring>

    ${syscall('SYS_faccessat', fd, file, type, flag)}
