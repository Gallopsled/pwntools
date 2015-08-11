
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="path, mode, dev"/>
<%docstring>
Invokes the syscall mknod.  See 'man 2 mknod' for more information.

Arguments:
    path(char): path
    mode(mode_t): mode
    dev(dev_t): dev
</%docstring>

    ${syscall('SYS_mknod', path, mode, dev)}
