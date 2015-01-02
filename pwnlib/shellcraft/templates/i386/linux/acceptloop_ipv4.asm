<% from pwnlib.shellcraft import common %>
<% from pwnlib.constants.linux import i386 as constants %>
<% from pwnlib.util.packing import make_packer %>
<% from socket import htons %>
<%page args="port"/>
<%docstring>
    Args: port
    Waits for a connection.  Leaves socket in EBP.
    ipv4 only
</%docstring>
<%
  acceptloop = common.label("acceptloop")
  looplabel = common.label("loop")
  p16  = make_packer(16, 'little', 'unsigned')
  p16b = make_packer(16, 'big', 'unsigned')
%>

${acceptloop}:
        /*  Listens for and accepts a connection on ${int(port)}d forever */
        /*  Socket file descriptor is placed in EBP */

        /*  sock = socket(AF_INET, SOCK_STREAM, 0) */
        ${i386.mov('eax', constants.SYS_socketcall)}
        ${i386.mov('ebx', constants.SYS_socketcall_socket)}
        cdq                     /*  clear EDX */
        push edx                /*  IPPROTO_IP (= 0) */
        push ebx                /*  SOCK_STREAM */
        push AF_INET
        ${i386.linux.syscall('eax', 'ebx', 'esp')}

        /*  bind(sock, &addr, sizeof addr); // sizeof addr == 0x10 */
        push edx
        ${i386.pushstr(p16(constants.AF_INET) + p16b(int(port)))}
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
        ${i386.linux.syscall('SYS_close', 'ebx')}

        test edi, edi
        jnz ${looplabel}
