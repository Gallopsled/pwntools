<% from pwnlib.shellcraft import aarch64 %>
<% from pwnlib.util.net import sockaddr %>
<% from pwnlib.constants import SOCK_STREAM, SOCK_DGRAM, SYS_socket %>
<%page args="network = 'ipv4', proto = 'tcp'"/>
<%docstring>
Creates a new socket
</%docstring>
<%
    if network == 'ipv4':
        sockaddr, length, address_family = sockaddr('127.0.0.1', 1, network)
    elif network == 'ipv6':
        sockaddr, length, address_family = sockaddr('::1', 1, network)
    socktype = {
        'tcp': SOCK_STREAM,
        'udp': SOCK_DGRAM
    }.get(proto, proto)
%>\
    /* open new socket */
    ${aarch64.linux.syscall(SYS_socket, address_family, socktype, 0)}
