<%
 from pwnlib.shellcraft.arm import push, mov, pushstr
 from pwnlib.shellcraft.arm.linux import syscall
 from pwnlib.constants import SOCK_STREAM, SYS_socket, SYS_connect
 from pwnlib.util.net import sockaddr
%>
<%page args="host, port, network='ipv4'"/>
<%docstring>
    Connects to the host on the specified port.
    Network is either 'ipv4' or 'ipv6'.
    Leaves the connected socket in R6.
</%docstring>
<%
    sockaddr, addr_len, address_family = sockaddr(host, port, network)
%>\
/* open new socket */
    ${syscall(SYS_socket, address_family, SOCK_STREAM, 0)}

/* save opened socket */
    ${mov('r6', 'r0')}

/* push sockaddr, connect() */
    ${pushstr(sockaddr, False)}
    ${syscall(SYS_connect, 'r6', 'sp', addr_len)}

/* Socket that is maybe connected is in r6 */
