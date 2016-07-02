<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="fd, dirp, count"/>
<%docstring>
Invokes the syscall getdents.  See 'man 2 getdents' for more information.

Arguments:
    fd(int): fd
    dirp(int): dirp
    count(int): count
</%docstring>

    ${syscall('SYS_getdents', fd, dirp, count)}
