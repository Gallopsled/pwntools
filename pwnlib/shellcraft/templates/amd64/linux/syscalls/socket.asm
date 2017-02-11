<% from pwnlib.shellcraft import amd64 %>
<% from pwnlib.util.net import sockaddr %>
<% from pwnlib.constants import SOCK_STREAM, SOCK_DGRAM, SYS_socket %>
<%page args="network = 'ipv4', proto = 'tcp'"/>
<%docstring>
Creates a new socket
</%docstring>
<%
    sockaddr, length, address_family = sockaddr('127.0.0.1', 1, network)
    socktype = {
        'tcp': SOCK_STREAM,
        'udp': SOCK_DGRAM
    }.get(proto, proto)
%>\
    /* open new socket */
    ${amd64.linux.syscall(SYS_socket, address_family, socktype, 0)}
