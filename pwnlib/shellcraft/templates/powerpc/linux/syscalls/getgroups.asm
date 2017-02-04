
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="size, list"/>
<%docstring>
Invokes the syscall getgroups.  See 'man 2 getgroups' for more information.

Arguments:
    size(int): size
    list(gid_t): list
</%docstring>

    ${syscall('SYS_getgroups', size, list)}
