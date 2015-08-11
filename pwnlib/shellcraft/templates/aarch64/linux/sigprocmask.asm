
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="how, set, oset, sigsetsize"/>
<%docstring>
Invokes the syscall sigprocmask.  See 'man 2 sigprocmask' for more information.

Arguments:
    how(int): how
    set(sigset_t): set
    oset(sigset_t): oset
    sigsetsize(size_t): sigsetsize
</%docstring>

    ${syscall('SYS_rt_sigprocmask', how, set, oset, sigsetsize)}
