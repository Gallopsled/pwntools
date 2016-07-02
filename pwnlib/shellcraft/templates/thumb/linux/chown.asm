
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="file, owner, group"/>
<%docstring>
Invokes the syscall chown.  See 'man 2 chown' for more information.

Arguments:
    file(char): file
    owner(uid_t): owner
    group(gid_t): group
</%docstring>

    ${syscall('SYS_chown', file, owner, group)}
