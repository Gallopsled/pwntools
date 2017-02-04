
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="rgid, egid, sgid"/>
<%docstring>
Invokes the syscall getresgid.  See 'man 2 getresgid' for more information.

Arguments:
    rgid(gid_t): rgid
    egid(gid_t): egid
    sgid(gid_t): sgid
</%docstring>

    ${syscall('SYS_getresgid', rgid, egid, sgid)}
