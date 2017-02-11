
<%
    from pwnlib.shellcraft.amd64.linux import syscall
%>
<%page args="fd, path, mode, dev"/>
<%docstring>
Invokes the syscall mknodat.  See 'man 2 mknodat' for more information.

Arguments:
    fd(int): fd
    path(char): path
    mode(mode_t): mode
    dev(dev_t): dev
</%docstring>

    ${syscall('SYS_mknodat', fd, path, mode, dev)}
