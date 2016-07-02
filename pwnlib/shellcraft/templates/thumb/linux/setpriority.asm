
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="which, who, prio"/>
<%docstring>
Invokes the syscall setpriority.  See 'man 2 setpriority' for more information.

Arguments:
    which(priority_which_t): which
    who(id_t): who
    prio(int): prio
</%docstring>

    ${syscall('SYS_setpriority', which, who, prio)}
