
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="n, groups"/>
<%docstring>
Invokes the syscall setgroups.  See 'man 2 setgroups' for more information.

Arguments:
    n(size_t): n
    groups(gid_t): groups
</%docstring>

    ${syscall('SYS_setgroups', n, groups)}
