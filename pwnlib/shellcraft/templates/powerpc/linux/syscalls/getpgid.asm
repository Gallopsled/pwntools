
<%
    from pwnlib.shellcraft.powerpc.linux import syscall
%>
<%page args="pid"/>
<%docstring>
Invokes the syscall getpgid.  See 'man 2 getpgid' for more information.

Arguments:
    pid(pid_t): pid
</%docstring>

    ${syscall('SYS_getpgid', pid)}
