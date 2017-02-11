
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="gid"/>
<%docstring>
Invokes the syscall setgid.  See 'man 2 setgid' for more information.

Arguments:
    gid(gid_t): gid
</%docstring>

    ${syscall('SYS_setgid', gid)}
