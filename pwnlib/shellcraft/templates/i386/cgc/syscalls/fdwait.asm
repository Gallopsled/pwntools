<%
    from pwnlib.shellcraft.i386.cgc import syscall
%>
<%page args="nfds, readfds, writefds, timeout, readyfds"/>
<%docstring>
Invokes the syscall fdwait.

For more information, see:
https://github.com/CyberGrandChallenge/libcgc/blob/master/fdwait.md

Arguments:
    nfds(int): nfds
    readfds(int): readfds
    writefds(int): writefds
    timeout(int): timeout
    readyfds(int): readyfds
</%docstring>

    ${syscall('SYS_fdwait', nfds, readfds, writefds, timeout, readyfds)}
