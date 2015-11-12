
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="name, length"/>
<%docstring>
Invokes the syscall sethostname.  See 'man 2 sethostname' for more information.

Arguments:
    name(char): name
    len(size_t): len
</%docstring>

    ${syscall('SYS_sethostname', name, length)}
