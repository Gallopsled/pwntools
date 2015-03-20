<% from pwnlib.shellcraft import amd64, common %>
<% from socket import htons %>
<%page args="port, network='ipv4'"/>
<%docstring>
    listen(port,network)

    Listens on a TCP port, accept a client and leave his socket in RAX.
    Port is the TCP port to listen on, network is either 'ipv4' or 'ipv6'.
</%docstring>
%if network == 'ipv4':
    ${amd64.linux.syscall('SYS_socket', 'AF_INET', 'SOCK_STREAM', 0)}
    /* Build sockaddr_in structure */
    push rdx
    ${amd64.mov('rdx', 'AF_INET | (%d << 16)' % htons(port))}
    push rdx
    /* rdx = sizeof(struct sockaddr_in6) */
    ${amd64.mov('rdx', 16)}
%else:
    ${amd64.linux.syscall('SYS_socket', 'AF_INET6', 'SOCK_STREAM', 0)}
    /* Build sockaddr_in6 structure */
    push rdx
    push rdx
    ${amd64.mov('rdx', 'AF_INET6 | (%d << 16)' % htons(port))}
    push rdx
    /* rdx = sizeof(struct sockaddr_in6) */
    ${amd64.mov('rdx', 28)}
%endif
    /* Save server socket in rbp */
    mov rbp, rax
    ${amd64.linux.syscall('SYS_bind', 'rax', 'rsp', 'rdx')}
    ${amd64.linux.syscall('SYS_listen', 'rbp', 1)}
    ${amd64.linux.syscall('SYS_accept', 'rbp', 0, 0)}
