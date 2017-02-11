
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="ruid, euid"/>
<%docstring>
Invokes the syscall setreuid.  See 'man 2 setreuid' for more information.

Arguments:
    ruid(uid_t): ruid
    euid(uid_t): euid
</%docstring>

    ${syscall('SYS_setreuid', ruid, euid)}
