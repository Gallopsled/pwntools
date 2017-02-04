
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="fd, file, oflag, vararg"/>
<%docstring>
Invokes the syscall openat.  See 'man 2 openat' for more information.

Arguments:
    fd(int): fd
    file(char): file
    oflag(int): oflag
    vararg(int): vararg
</%docstring>

    ${syscall('SYS_openat', fd, file, oflag, vararg)}
