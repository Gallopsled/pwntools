<%
    from pwnlib.shellcraft.i386.cgc import syscall
%>
<%page args="status"/>
<%docstring>
Invokes the syscall terminate.

For more information, see:
https://github.com/CyberGrandChallenge/libcgc/blob/master/_terminate.md

Arguments:
    status(int): status
</%docstring>

    ${syscall('SYS_terminate', status)}
