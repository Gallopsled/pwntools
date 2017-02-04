
<%
    from pwnlib.shellcraft.aarch64.linux import setsockopt
    from pwnlib.shellcraft.aarch64 import mov
    from pwnlib.constants import SOL_SOCKET, SO_RCVTIMEO
%>
<%page args="sock, secs"/>
<%docstring>
Invokes the syscall for setsockopt with specified timeout.  See 'man 2 setsockopt' for more information.

Arguments:
    sock(int): sock
    secs(int): secs
</%docstring>
    eor x4, x4, x4
    ${mov('x3', secs)}
    stp x3, x4, [sp, #-16]!
    ${setsockopt(sock, 'SOL_SOCKET', 'SO_RCVTIMEO', 'sp', 16)}

