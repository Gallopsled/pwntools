
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="set"/>
<%docstring>
Invokes the syscall sigpending.  See 'man 2 sigpending' for more information.

Arguments:
    set(sigset_t): set
</%docstring>

    ${syscall('SYS_sigpending', set)}
