<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import amd64 %> 
<% import socket %>
<% from pwnlib.util import packing %>

<%page args="host, port, network = 'ipv4'"/>
<%docstring>
    Connects to the host on the specified port.
    Network is either 'ipv4' or 'ipv6'.
    Leaves the connected socket in rbp.
</%docstring>
<%
    if network == 'ipv4':
        address_family = socket.AF_INET
    else:
        address_family = socket.AF_INET6
    
    info = socket.getaddrinfo(host, None, address_family)
    host = socket.inet_pton(address_family, info[0][4][0])
    sockaddr  = packing.p16(address_family)
    sockaddr += packing.p16(socket.htons(port))

    if network == 'ipv4':
        sockaddr += host
        sockaddr += '\x00' * (16 - len(sockaddr))
    else:
        sockaddr += packing.p32(0)
        sockaddr += host
        sockaddr += packing.p32(0)
%>\
    /* open new socket */
    ${amd64.linux.syscall('SYS_socket', address_family, 'SOCK_STREAM', 0)}
    
    /* Put socket into rbp */
    mov rbp, rax
    
    /* Create address structure on stack */
    ${amd64.pushstr(sockaddr, False)}
    
    /* Connect the socket */
    ${amd64.linux.syscall('SYS_connect', 'rbp', 'rsp', len(sockaddr))}
