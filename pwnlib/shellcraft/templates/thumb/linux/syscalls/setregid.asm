
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="rgid, egid"/>
<%docstring>
Invokes the syscall setregid.  See 'man 2 setregid' for more information.

Arguments:
    rgid(gid_t): rgid
    egid(gid_t): egid
</%docstring>

    ${syscall('SYS_setregid', rgid, egid)}
