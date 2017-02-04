
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="fd, offset, count"/>
<%docstring>
Invokes the syscall readahead.  See 'man 2 readahead' for more information.

Arguments:
    fd(int): fd
    offset(off64_t): offset
    count(size_t): count
</%docstring>

    ${syscall('SYS_readahead', fd, offset, count)}
