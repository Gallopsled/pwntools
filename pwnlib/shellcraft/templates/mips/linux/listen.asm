<% 
    from pwnlib.shellcraft import mips
    from pwnlib.util.net import sockaddr
%>
<% from socket import htons %>
<%page args="port, network='ipv4'"/>
<%docstring>
    listen(port,network)

    Listens on a TCP port, accept a client and leave his socket in $s0.
    Port is the TCP port to listen on, network is either 'ipv4' or 'ipv6'.
</%docstring>
<%
    sock_addr, addr_len, address_family = sockaddr('0.0.0.0', port, network)
%>\
    ${mips.syscall('SYS_socket', address_family, 'SOCK_STREAM', 0)}

    /* Save socket in $s0 */
    ${mips.mov('$s0', '$v0')}

    /* Build sockaddr_in structure */
    ${mips.pushstr(sock_addr)}
    ${mips.mov('$a1', '$sp')}

    ${mips.syscall('SYS_bind', '$s0', '$a1', addr_len)}

    ${mips.syscall('SYS_listen', '$s0', 1)}

    ${mips.syscall('SYS_accept', '$s0', 0, 0)}

    /* Move accepted socket to $s0 */
    ${mips.mov('$s0', '$v0')}
