
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="fd, vmessages, vlen, flags, tmo"/>
<%docstring>
Invokes the syscall recvmmsg.  See 'man 2 recvmmsg' for more information.

Arguments:
    fd(int): fd
    vmessages(mmsghdr): vmessages
    vlen(unsigned): vlen
    flags(int): flags
    tmo(timespec): tmo
</%docstring>

    ${syscall('SYS_recvmmsg', fd, vmessages, vlen, flags, tmo)}
