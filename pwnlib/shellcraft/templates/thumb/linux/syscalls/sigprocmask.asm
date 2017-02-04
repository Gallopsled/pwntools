
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="how, set, oset"/>
<%docstring>
Invokes the syscall sigprocmask.  See 'man 2 sigprocmask' for more information.

Arguments:
    how(int): how
    set(sigset_t): set
    oset(sigset_t): oset
</%docstring>

    ${syscall('SYS_sigprocmask', how, set, oset)}
