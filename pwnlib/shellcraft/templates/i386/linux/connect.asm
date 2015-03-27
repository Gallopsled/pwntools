<% from pwnlib.shellcraft import i386 %>
<% from pwnlib.util.net import sockaddr %>

<%page args="host, port, network = 'ipv4'"/>
<%docstring>
    Connects to the host on the specified port.
    Network is either 'ipv4' or 'ipv6'.
    Leaves the connected socket in ebp
</%docstring>
<%
    sockaddr, address_family = sockaddr(host, port, network)
%>\

/* open new socket */
push SYS_socketcall
pop eax
push SYS_socketcall_socket
pop ebx
cdq
push edx
push ebx
push ${address_family}
mov ecx, esp
int 0x80

/* save opened socket */
mov ebp, eax

${i386.pushstr(sockaddr, False)}

mov ecx, esp
push ${len(sockaddr)}
push ecx
push eax
mov ecx, esp
inc ebx
inc ebx
mov al, SYS_socketcall
int 0x80

/* Socket that is maybe connected is in ebp */
