<% from pwnlib.shellcraft import i386, common %>
<% from pwnlib.util.net import sockaddr %>
<% from socket import htons %>
<%page args="port, network='ipv4'"/>
<%docstring>
    listen(port,network)

    Listens on a TCP port, accept a client and leave his socket in EAX.
    Port is the TCP port to listen on, network is either 'ipv4' or 'ipv6'.
</%docstring>
<%
    if network == 'ipv4':
        bind_addr = '0.0.0.0'
    else:
        bind_addr = '::'
    sock_addr, addr_len, address_family = sockaddr(bind_addr, port, network)
%>\
/* First open socket */
${i386.push(0)}
${i386.push('SOCK_STREAM')}
${i386.push(address_family)}
${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_socket', 'esp')}

/* Save socket */
mov ebp, eax

/* Build sockaddr_in structure */
${i386.pushstr(sock_addr)}
mov eax, esp

/* Bind socket */
${i386.push(addr_len)}
${i386.push('eax')}
${i386.push('ebp')}
${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_bind', 'esp')}

/* Listen */
${i386.push(1)}
${i386.push('ebp')}
${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_listen', 'esp')}

/* Accept */
${i386.push(0)}
${i386.push(0)}
${i386.push('ebp')}
${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_accept', 'esp')}
