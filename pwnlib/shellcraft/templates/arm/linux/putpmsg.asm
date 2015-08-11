
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fildes, ctlptr, dataptr, band, flags"/>
<%docstring>
Invokes the syscall putpmsg.  See 'man 2 putpmsg' for more information.

Arguments:
    fildes(int): fildes
    ctlptr(strbuf): ctlptr
    dataptr(strbuf): dataptr
    band(int): band
    flags(int): flags
</%docstring>

    ${syscall('SYS_putpmsg', fildes, ctlptr, dataptr, band, flags)}
