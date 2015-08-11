
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="rgid, egid, sgid"/>
<%docstring>
Invokes the syscall setresgid.  See 'man 2 setresgid' for more information.

Arguments:
    rgid(gid_t): rgid
    egid(gid_t): egid
    sgid(gid_t): sgid
</%docstring>

    ${syscall('SYS_setresgid', rgid, egid, sgid)}
