
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="who, usage"/>
<%docstring>
Invokes the syscall getrusage.  See 'man 2 getrusage' for more information.

Arguments:
    who(rusage_who_t): who
    usage(rusage): usage
</%docstring>

    ${syscall('SYS_getrusage', who, usage)}
