
<%
    from pwnlib.shellcraft.i386.linux import syscall
%>
<%page args="fn, child_stack, flags, arg, vararg"/>
<%docstring>
Invokes the syscall clone.  See 'man 2 clone' for more information.

Arguments:
    fn(int): fn
    child_stack(void): child_stack
    flags(int): flags
    arg(void): arg
    vararg(int): vararg
</%docstring>

    ${syscall('SYS_clone', fn, child_stack, flags, arg, vararg)}
