
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="from, tofd, to"/>
<%docstring>
Invokes the syscall symlinkat.  See 'man 2 symlinkat' for more information.

Arguments:
    from(char): from
    tofd(int): tofd
    to(char): to
</%docstring>

    ${syscall('SYS_symlinkat', from, tofd, to)}
