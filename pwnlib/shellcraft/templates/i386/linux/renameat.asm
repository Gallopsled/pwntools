
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="oldfd, old, newfd, new"/>
<%docstring>
Invokes the syscall renameat.  See 'man 2 renameat' for more information.

Arguments:
    oldfd(int): oldfd
    old(char): old
    newfd(int): newfd
    new(char): new
</%docstring>

    ${syscall('SYS_renameat', oldfd, old, newfd, new)}
