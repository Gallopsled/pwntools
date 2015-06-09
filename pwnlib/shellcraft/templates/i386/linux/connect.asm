<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.i386 import push, pushstr %>
<% from pwnlib.shellcraft.i386.linux import syscall %>
<% from pwnlib.constants import SOCK_STREAM, AF_INET, SYS_socketcall, SYS_socketcall_socket, SYS_socketcall_connect %>
<% from socket import htons, inet_aton, gethostbyname %>
<% from pwnlib.util import packing %>
<% from pwnlib.shellcraft import i386 %>
<% from pwnlib.util.net import sockaddr %>

<%page args="host, port, network = 'ipv4'"/>
<%docstring>
Connects to the host on the specified port.
Leaves the connected socket in ebp

Arguments:
    host(str): Remote IP address or hostname (as a dotted quad / string)
    port(int): Remote port
    network(str): Network protocol (ipv4 or ipv6)

Examples:

    >>> with context.local(arch='i386', os='linux'):
    ...     print enhex(asm(shellcraft.connect('localhost', 0x1000)))
    ...     print enhex(asm(shellcraft.connect('localhost', 0x1000, 'ipv6')))
    6a01fe0c246a016a026a015b89e16a665899cd8089c568010101028134247e01010368010101018134240301110189e16a1051556a035b89e16a6658cd80
    6a01fe0c246a016a0bfe0c246a015b89e16a665899cd8089c56801010102813424010101036a01fe0c246a01fe0c246a01fe0c246aff68010101018134240b01110189e16a1c51556a035b89e16a6658cd80

    Connects to the host on the specified port.
    Network is either 'ipv4' or 'ipv6'.
    Leaves the connected socket in ebp
</%docstring>
<%
    sockaddr, length, address_family = sockaddr(host, port, network)
%>\

/* open new socket */
    ${push(0)}
    ${push(SOCK_STREAM)}
    ${push(address_family)}
    ${syscall(SYS_socketcall, SYS_socketcall_socket, 'esp', 0)}

/* save opened socket */
    mov ebp, eax

/* push sockaddr, connect() */
    ${pushstr(sockaddr, False)}
    mov ecx, esp
    ${push(length)} /* socklen_t addrlen */
    push ecx    /* sockaddr *addr */
    push ebp    /* sockfd */
    ${syscall(SYS_socketcall, SYS_socketcall_connect, 'esp')}

/* Socket that is maybe connected is in ebp */
