
<%
    from pwnlib.shellcraft.thumb.linux import syscall
%>
<%page args="flags"/>
<%docstring>
Invokes the syscall unshare.  See 'man 2 unshare' for more information.

Arguments:
    flags(int): flags
</%docstring>

    ${syscall('SYS_unshare', flags)}
