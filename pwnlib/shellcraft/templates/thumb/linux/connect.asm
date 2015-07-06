<% from pwnlib.shellcraft import thumb %>
<% from pwnlib.util.net import sockaddr %>
<%page args="host, port, network='ipv4'"/>
<%docstring>
    Connects to the host on the specified port.
    Network is either 'ipv4' or 'ipv6'.
    Leaves the connected socket in R6.
</%docstring>
<%
    sockaddr, addr_len, address_family = sockaddr(host, port, network)
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
    ${thumb.mov('r2', addr_len)}
    svc 1
