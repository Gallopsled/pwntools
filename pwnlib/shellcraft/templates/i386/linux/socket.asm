<% from pwnlib.shellcraft.i386.linux import socketcall %>
<% from pwnlib.constants import AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM, SYS_socketcall_socket %>
<% from pwnlib.util.net import sockaddr %>
<%page args="network = 'ipv4', proto = 'tcp'"/>
<%docstring>
Creates a new socket
</%docstring>
<%
    address_family = {'ipv4':AF_INET,'ipv6':AF_INET6}.get(network, network)
%>\
    /* open new socket */
    ${socketcall(SYS_socketcall_socket, address_family, SOCK_STREAM, 0)}
