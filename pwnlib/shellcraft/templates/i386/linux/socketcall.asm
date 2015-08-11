<% from pwnlib.shellcraft import common, pretty %>
<% from pwnlib.shellcraft.i386 import push %>
<% from pwnlib.shellcraft.i386.linux import syscall %>
<% from pwnlib.constants import SYS_socketcall %>

<%page args="socketcall, socket, sockaddr, sockaddr_len"/>
<%docstring>
Invokes a socket call (e.g. socket, send, recv, shutdown)
</%docstring>

    /* socketcall(${pretty(socket,0)}, ${pretty(sockaddr,0)}, ${pretty(sockaddr_len,0)}) */
    ${push(sockaddr_len)} /* socklen_t addrlen */
    ${push(sockaddr)}     /* sockaddr *addr */
    ${push(socket)}       /* sockfd */
    ${syscall('SYS_socketcall', socketcall, 'esp')}
