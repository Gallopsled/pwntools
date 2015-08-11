
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args="fd, iovec, count, offset"/>
<%docstring>
Invokes the syscall preadv.  See 'man 2 preadv' for more information.

Arguments:
    fd(int): fd
    iovec(iovec): iovec
    count(int): count
    offset(off_t): offset
</%docstring>

    ${syscall('SYS_preadv', fd, iovec, count, offset)}
