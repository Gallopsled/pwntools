<%
    from pwnlib import shellcraft
    from pwnlib.util.packing import flat, unpack
    from pwnlib.util.iters import group
%>
<%page args="value, register1='x14', register2='x15'"/>
<%docstring>
Pushes a value onto the stack without using null bytes or newline characters.

If src is a string, then we try to evaluate using :func:`pwnlib.constants.eval`
before determining how to push it.

Note that this means that this shellcode can change behavior depending on
the value of `context.os`.

Note:
    AArch64 requires that the stack remain 16-byte aligned at all times,
    so this alignment is preserved.

Args:
    value(int,str): The value or register to push
    register1(str): Scratch register to use
    register2(str): Second scratch register to use

Example:

    >>> print(pwnlib.shellcraft.push(0).rstrip())
        /* push 0 */
        mov  x14, xzr
        str x14, [sp, #-16]!
    >>> print(pwnlib.shellcraft.push(1).rstrip())
        /* push 1 */
        mov  x14, #1
        str x14, [sp, #-16]!
    >>> print(pwnlib.shellcraft.push(256).rstrip())
        /* push 0x100 */
        mov  x14, #256
        str x14, [sp, #-16]!
    >>> print(pwnlib.shellcraft.push('SYS_execve').rstrip())
        /* push SYS_execve (0xdd) */
        mov  x14, #221
        str x14, [sp, #-16]!
    >>> print(pwnlib.shellcraft.push('SYS_sendfile').rstrip())
        /* push SYS_sendfile (0x47) */
        mov  x14, #71
        str x14, [sp, #-16]!
    >>> with context.local(os = 'freebsd'):
    ...     print(pwnlib.shellcraft.push('SYS_execve').rstrip())
    ...
        /* push SYS_execve (0x3b) */
        mov  x14, #59
        str x14, [sp, #-16]!
</%docstring>
<%
if isinstance(value, str):
    value = shellcraft.eval(value)
pretty = shellcraft.pretty(value, comment=False)
%>
    ${shellcraft.pushstr(flat(value),
                         append_null = False,
                         register1 = register1,
                         register2 = register2,
                         pretty = pretty)}
