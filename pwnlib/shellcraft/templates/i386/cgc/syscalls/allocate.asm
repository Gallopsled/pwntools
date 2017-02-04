<%
    from pwnlib.shellcraft.i386.cgc import syscall
%>
<%page args="length, is_X, addr"/>
<%docstring>
Invokes the syscall allocate.

For more information, see:
https://github.com/CyberGrandChallenge/libcgc/blob/master/allocate.md

Arguments:
    length(int): length
    is_X(int): is_X
    addr(int): addr
</%docstring>

    ${syscall('SYS_allocate', length, is_X, addr)}
