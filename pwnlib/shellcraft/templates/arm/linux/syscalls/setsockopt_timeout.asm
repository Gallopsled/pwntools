
<%
    from pwnlib.shellcraft.arm.linux import setsockopt
    from pwnlib.shellcraft.arm import push
    from pwnlib.shellcraft.arm import mov
    from pwnlib.constants import SOL_SOCKET, SO_RCVTIMEO
%>
<%page args="sock, secs"/>
<%docstring>
Invokes the syscall for setsockopt with specified timeout.  See 'man 2 setsockopt' for more information.

Arguments:
    sock(int): sock
    secs(int): secs
</%docstring>
    eor r4, r4, r4
    push {r4}
    ${mov('r4', secs)}
    push {r4}
    ${setsockopt(sock, 'SOL_SOCKET', 'SO_RCVTIMEO', 'sp', 8)}

