<%
    from pwnlib.shellcraft.i386.cgc import syscall
%>
<%page args="addr, length"/>
<%docstring>
Invokes the syscall deallocate.

For more information, see:
https://github.com/CyberGrandChallenge/libcgc/blob/master/deallocate.md

Arguments:
    addr(int): addr
    length(int): length
</%docstring>

    ${syscall('SYS_deallocate', addr, length)}
