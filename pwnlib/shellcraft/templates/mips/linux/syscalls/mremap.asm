
<%
    from pwnlib.shellcraft.mips.linux import syscall
%>
<%page args="addr, old_len, new_len, flags, vararg"/>
<%docstring>
Invokes the syscall mremap.  See 'man 2 mremap' for more information.

Arguments:
    addr(void): addr
    old_len(size_t): old_len
    new_len(size_t): new_len
    flags(int): flags
    vararg(int): vararg
</%docstring>

    ${syscall('SYS_mremap', addr, old_len, new_len, flags, vararg)}
