
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="fildes, ctlptr, dataptr, bandp, flagsp"/>
<%docstring>
Invokes the syscall getpmsg.  See 'man 2 getpmsg' for more information.

Arguments:
    fildes(int): fildes
    ctlptr(strbuf): ctlptr
    dataptr(strbuf): dataptr
    bandp(int): bandp
    flagsp(int): flagsp
</%docstring>

    ${syscall('SYS_getpmsg', fildes, ctlptr, dataptr, bandp, flagsp)}
