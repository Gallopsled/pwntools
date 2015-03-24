<% import socket %>
<% from pwnlib.util import packing %>
<%page args="host, port, network = 'ipv4'"/>
<%docstring>
Returns a sockaddr_in or sockaddr_in6 structure for the specified host, port and network.
Args:
  host (str): IP address or hostname
  port (int): TCP/UDP port
  network (str): Either 'ipv4' (default) or 'ipv6'
</%docstring>
<%
    address_family = {'ipv4':socket.AF_INET,'ipv6':socket.AF_INET6}[network]
    
    info = socket.getaddrinfo(host, None, address_family)
    host = socket.inet_pton(address_family, info[0][4][0])
    sockaddr  = packing.p16(address_family)
    sockaddr += packing.p16(socket.htons(port))

    if network == 'ipv4':
        sockaddr += host
        sockaddr = sockaddr.ljust(16, '\x00')
    else:
        sockaddr += packing.p32(0)
        sockaddr += host
        sockaddr += packing.p32(0)
%>\
${sockaddr}
