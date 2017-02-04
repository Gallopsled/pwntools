
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="file, owner, group"/>
<%docstring>
Invokes the syscall lchown.  See 'man 2 lchown' for more information.

Arguments:
    file(char): file
    owner(uid_t): owner
    group(gid_t): group
</%docstring>

    ${syscall('SYS_lchown', file, owner, group)}
