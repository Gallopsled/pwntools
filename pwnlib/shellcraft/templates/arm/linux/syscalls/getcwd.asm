
<%
    from pwnlib.shellcraft.arm.linux import syscall
%>
<%page args="buf, size"/>
<%docstring>
Invokes the syscall getcwd.  See 'man 2 getcwd' for more information.

Arguments:
    buf(char): buf
    size(size_t): size
</%docstring>

    ${syscall('SYS_getcwd', buf, size)}
