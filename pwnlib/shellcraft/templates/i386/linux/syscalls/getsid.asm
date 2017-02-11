
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="pid"/>
<%docstring>
Invokes the syscall getsid.  See 'man 2 getsid' for more information.

Arguments:
    pid(pid_t): pid
</%docstring>

    ${syscall('SYS_getsid', pid)}
