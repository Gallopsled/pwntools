
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="set"/>
<%docstring>
Invokes the syscall sigsuspend.  See 'man 2 sigsuspend' for more information.

Arguments:
    set(sigset_t): set
</%docstring>

    ${syscall('SYS_sigsuspend', set)}
