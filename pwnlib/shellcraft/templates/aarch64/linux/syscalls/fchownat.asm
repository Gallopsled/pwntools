
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="fd, file, owner, group, flag"/>
<%docstring>
Invokes the syscall fchownat.  See 'man 2 fchownat' for more information.

Arguments:
    fd(int): fd
    file(char): file
    owner(uid_t): owner
    group(gid_t): group
    flag(int): flag
</%docstring>

    ${syscall('SYS_fchownat', fd, file, owner, group, flag)}
