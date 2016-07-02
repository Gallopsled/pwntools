
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="fd, owner, group"/>
<%docstring>
Invokes the syscall fchown.  See 'man 2 fchown' for more information.

Arguments:
    fd(int): fd
    owner(uid_t): owner
    group(gid_t): group
</%docstring>

    ${syscall('SYS_fchown', fd, owner, group)}
