
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="which, who"/>
<%docstring>
Invokes the syscall getpriority.  See 'man 2 getpriority' for more information.

Arguments:
    which(priority_which_t): which
    who(id_t): who
</%docstring>

    ${syscall('SYS_getpriority', which, who)}
