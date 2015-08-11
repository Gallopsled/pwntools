
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="name"/>
<%docstring>
Invokes the syscall uname.  See 'man 2 uname' for more information.

Arguments:
    name(utsname): name
</%docstring>

    ${syscall('SYS_uname', name)}
