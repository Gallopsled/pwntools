
<%
    from pwnlib.shellcraft.i386.linux import setsockopt
    from pwnlib.shellcraft.i386 import push
    from pwnlib.constants import SOL_SOCKET, SO_RCVTIMEO
%>
<%page args="sock, secs"/>
<%docstring>
Invokes the syscall fork.  See 'man 2 fork' for more information.

Arguments:
    sock(int): sock
    secs(int): secs
</%docstring>
    ${push(0)}
    ${push(secs)}
    mov edi, esp
    ${setsockopt(sock, 'SOL_SOCKET', 'SO_RCVTIMEO', 'edi', 8)}
    add esp, 28
