
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="ruid, euid, suid"/>
<%docstring>
Invokes the syscall getresuid.  See 'man 2 getresuid' for more information.

Arguments:
    ruid(uid_t): ruid
    euid(uid_t): euid
    suid(uid_t): suid
</%docstring>

    ${syscall('SYS_getresuid', ruid, euid, suid)}
