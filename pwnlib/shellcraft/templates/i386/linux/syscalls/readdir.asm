
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="dirp"/>
<%docstring>
Invokes the syscall readdir.  See 'man 2 readdir' for more information.

Arguments:
    dirp(DIR): dirp
</%docstring>

    ${syscall('SYS_readdir', dirp)}
