<% from pwnlib.shellcraft.i386 import pushstr %>
<% from pwnlib.shellcraft.i386.linux import socket, socketcall %>
<% from pwnlib.constants import SYS_socketcall_connect %>
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

    >>> l = listen(timeout=5)
    >>> assembly  = shellcraft.i386.linux.connect('localhost', l.lport)
    >>> assembly += shellcraft.i386.pushstr('Hello')
    >>> assembly += shellcraft.i386.linux.write('edx', 'esp', 5)
    >>> p = run_assembly(assembly)
    >>> l.wait_for_connection().recv()
    b'Hello'

    >>> l = listen(fam='ipv6', timeout=5)
    >>> assembly = shellcraft.i386.linux.connect('::1', l.lport, 'ipv6')
    >>> p = run_assembly(assembly)
    >>> assert l.wait_for_connection()

</%docstring>
<%
    sockaddr, length, address_family = sockaddr(host, port, network)
%>\

/* open new socket, save it */
    ${socket(network)}
    mov edx, eax

/* push sockaddr, connect() */
    ${pushstr(sockaddr, False)}
    mov ecx, esp
    ${socketcall(SYS_socketcall_connect, 'edx', 'ecx', length)}

/* Socket that is maybe connected is in edx */
