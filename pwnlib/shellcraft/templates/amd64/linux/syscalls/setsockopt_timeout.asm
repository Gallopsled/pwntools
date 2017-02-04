
<%
    from pwnlib.shellcraft.amd64.linux import setsockopt
    from pwnlib.shellcraft.amd64 import push
    from pwnlib.constants import SOL_SOCKET, SO_RCVTIMEO
%>
<%page args="sock, secs"/>
<%docstring>
Invokes the syscall for setsockopt to set a timeout on a socket in seconds.
See 'man 2 setsockopt' for more information.

Arguments:
    sock(int): sock
    secs(int): secs
</%docstring>
    ${push(0)}
    ${push(secs)}
    ${setsockopt(sock, 'SOL_SOCKET', 'SO_RCVTIMEO', 'rsp', 16)}

