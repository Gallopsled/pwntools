
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fd, message, flags"/>
<%docstring>
Invokes the syscall recvmsg.  See 'man 2 recvmsg' for more information.

Arguments:
    fd(int): fd
    message(msghdr): message
    flags(int): flags
</%docstring>

    ${syscall('SYS_recvmsg', fd, message, flags)}
