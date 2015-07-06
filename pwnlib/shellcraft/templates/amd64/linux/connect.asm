<% from pwnlib.shellcraft import amd64 %>
<% from pwnlib.util.net import sockaddr %>

<%page args="host, port, network = 'ipv4'"/>
<%docstring>
    Connects to the host on the specified port.
    Network is either 'ipv4' or 'ipv6'.
    Leaves the connected socket in rbp.
</%docstring>
<%
    sockaddr, addr_len, address_family = sockaddr(host, port, network)
%>\
    /* open new socket */
    ${amd64.linux.syscall('SYS_socket', address_family, 'SOCK_STREAM', 0)}
    
    /* Put socket into rbp */
    mov rbp, rax
    
    /* Create address structure on stack */
    ${amd64.pushstr(sockaddr, False)}
    
    /* Connect the socket */
    ${amd64.linux.syscall('SYS_connect', 'rbp', 'rsp', addr_len)}
