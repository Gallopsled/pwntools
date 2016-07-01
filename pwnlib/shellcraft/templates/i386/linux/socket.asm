<% from pwnlib.shellcraft.i386.linux import socketcall %>
<% from pwnlib.constants import AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM, SYS_socketcall_socket %>
<% from pwnlib.util.net import sockaddr %>
<%page args="network = 'ipv4', proto = 'tcp'"/>
<%docstring>
Creates a new socket

Arguments:
    network(str): ipv4 or ipv6
    proto(str): tcp or udp
</%docstring>
<%
    address_family = {'ipv4':AF_INET,'ipv6':AF_INET6}.get(network, network)
    proto          = {'tcp':SOCK_STREAM, SOCK_STREAM: SOCK_STREAM,
                      'udp':SOCK_DGRAM,  SOCK_DGRAM:  SOCK_DGRAM}[proto]
%>\
    /* open new socket */
    ${socketcall(SYS_socketcall_socket, address_family, proto, 0)}
