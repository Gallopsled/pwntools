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
Leaves the connected socket in edx

Arguments:
    host(str): Remote IP address or hostname (as a dotted quad / string)
    port(int): Remote port
    network(str): Network protocol (ipv4 or ipv6)

Examples:

    >>> l = listen(timeout=1)
    >>> assembly  = shellcraft.i386.linux.connect('localhost', l.lport)
    >>> assembly += shellcraft.i386.pushstr('Hello')
    >>> assembly += shellcraft.i386.linux.write('edx', 'esp', 5)
    >>> run_assembly(assembly)
    >>> l.wait_for_connection().recv()
    'Hello'

    >>> l = listen(fam='ipv6', timeout=1)
    >>> assembly   = shellcraft.i386.linux.connect('localhost', l.lport, 'ipv6')
    >>> run_assembly(assembly)
    >>> assert l.wait_for_connection()

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
    mov edx, eax

/* push sockaddr, connect() */
    ${pushstr(sockaddr, False)}
    mov ecx, esp
    ${push(length)} /* socklen_t addrlen */
    push ecx    /* sockaddr *addr */
    push edx    /* sockfd */
    ${syscall(SYS_socketcall, SYS_socketcall_connect, 'esp')}

/* Socket that is maybe connected is in edx */
