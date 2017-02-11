
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="uid"/>
<%docstring>
Invokes the syscall setuid.  See 'man 2 setuid' for more information.

Arguments:
    uid(uid_t): uid
</%docstring>

    ${syscall('SYS_setuid', uid)}
