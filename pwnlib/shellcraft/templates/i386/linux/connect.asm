<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.i386 import push, pushstr %>
<% from pwnlib.shellcraft.i386.linux import syscall %>
<% from pwnlib.constants import SOCK_STREAM, AF_INET, SYS_socketcall, SYS_socketcall_socket, SYS_socketcall_connect %>
<% from socket import htons, inet_aton, gethostbyname %>
<% from pwnlib.util import packing %>

<%page args="host, port"/>
<%docstring>
Connects to the host on the specified port.
Leaves the connected socket in ebp

Examples:

    >>> with context.local(arch='i386', os='linux'):
    ...     print enhex(asm(shellcraft.connect('localhost', 0x1000)))
    6a01fe0c246a016a026a015b89e16a665899cd8089c568010101028134247e01010368010101018134240301110189e16a1051556a035b89e16a6658cd80
</%docstring>

/* open new socket */
    ${push(0)}
    ${push(SOCK_STREAM)}
    ${push(AF_INET)}
    ${syscall(SYS_socketcall, SYS_socketcall_socket, 'esp', 0)}

/* save opened socket */
    mov ebp, eax

<%
   ip_addr = gethostbyname(str(host))
   sin_family_port = AF_INET | (htons(port) << 16)
%>
/* ${repr(host)} == ${ip_addr} */
    ${pushstr(inet_aton(ip_addr), False)}
    ${push(sin_family_port)}
    mov ecx, esp
    ${push(16)} /* socklen_t addrlen */
    push ecx    /* sockaddr *addr */
    push ebp    /* sockfd */
    ${syscall(SYS_socketcall, SYS_socketcall_connect, 'esp')}

/* Socket that is maybe connected is in ebp */
