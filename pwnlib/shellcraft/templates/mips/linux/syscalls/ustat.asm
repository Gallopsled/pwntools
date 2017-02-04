
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="dev, ubuf"/>
<%docstring>
Invokes the syscall ustat.  See 'man 2 ustat' for more information.

Arguments:
    dev(dev_t): dev
    ubuf(ustat): ubuf
</%docstring>

    ${syscall('SYS_ustat', dev, ubuf)}
