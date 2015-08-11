
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="name, oflag, vararg"/>
<%docstring>
Invokes the syscall mq_open.  See 'man 2 mq_open' for more information.

Arguments:
    name(char): name
    oflag(int): oflag
    vararg(int): vararg
</%docstring>

    ${syscall('SYS_mq_open', name, oflag, vararg)}
