<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft import amd64 %>
<% from socket import htons %>
<%page args="port = None"/>
<%docstring>
Args: port (defaults to any port)
    Finds a socket, which is connected to the specified port.
    Leaves socket in RDI.
</%docstring>
<%
  findpeer = common.label("findpeer")
  looplabel = common.label("loop")
%>

${findpeer}:
    /* File descriptor in rdi */
    ${amd64.mov('rdi', -1)}
    /* struct sockaddr * in rsi */
    mov rsi, rsp
    /* Size of address structure */
    ${amd64.push(32)}

${looplabel}:
    /* Next file descriptor */
    inc rdi
    /* See if it is a valid socket */
    ${amd64.linux.syscall('SYS_getpeername', 'rdi', 'rsi', 'rsp')}

    /* Was it successful? */
    test eax, eax

    /* No? Try the next */
    jnz ${looplabel}

%if not port is None:
    /* Check if port is right */
    lea rax, [rsp + 10]
    mov ax, [rax]
    cmp ax, ${htons(int(port))}
    jne ${looplabel}
%endif
    /* Socket found, it is in RDI */
