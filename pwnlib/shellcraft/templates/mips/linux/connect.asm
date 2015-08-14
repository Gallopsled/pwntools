<% 
    from pwnlib.shellcraft import mips
    from pwnlib.util.net import sockaddr
%>
<%page args="host, port, network='ipv4'"/>
<%docstring>
    Connects to the host on the specified port.
    Network is either 'ipv4' or 'ipv6'.
    Leaves the connected socket in $s0.
</%docstring>
<%
    sockaddr, addr_len, address_family = sockaddr(host, port, network)
%>\
    /* First create socket */
    ${mips.syscall('SYS_socket', address_family, 'SOCK_STREAM', 0)}
    ${mips.mov('$s0', '$v0')}

    /* Create address structure on stack */
    ${mips.pushstr(sockaddr, False)}

    /* Connect the socket */
    ${mips.syscall('SYS_connect', '$s0', '$sp', addr_len)}
