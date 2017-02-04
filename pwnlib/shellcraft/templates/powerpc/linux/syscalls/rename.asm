
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="old, new"/>
<%docstring>
Invokes the syscall rename.  See 'man 2 rename' for more information.

Arguments:
    old(char): old
    new(char): new
</%docstring>

    ${syscall('SYS_rename', old, new)}
