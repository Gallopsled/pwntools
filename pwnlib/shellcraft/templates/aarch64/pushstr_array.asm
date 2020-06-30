<%
    from pwnlib import shellcraft
    from pwnlib.context import context as ctx
    from pwnlib.util.iters import group
    from six import text_type, binary_type
%>
<%docstring>
Pushes an array/envp-style array of pointers onto the stack.

Arguments:
    reg(str):
        Destination register to hold the pointer.
    array(str,list):
        Single argument or list of arguments to push.
        NULL termination is normalized so that each argument
        ends with exactly one NULL byte.

Example:
    >>> assembly = shellcraft.execve("/bin/sh", ["sh", "-c", "echo Hello string $WORLD"], {"WORLD": "World!"})
    >>> ELF.from_assembly(assembly).process().recvall()
    b'Hello, World!\n'

    >>> assembly = shellcraft.execve(b"/bin/sh", [b"sh", b"-c", b"echo Hello binary $WORLD"], {b"WORLD": b"World!"})
    >>> ELF.from_assembly(assembly).process().recvall()
    b'Hello, World!\n'
</%docstring>
<%page args="reg, array, register1='x14', register2='x15'"/>
<%
if isinstance(array, (binary_type, text_type)):
    array = [array]

# Normalize line endings for each item
array = [arg.rstrip(b'\x00') + b'\x00' for arg in array]

# Join everything in the string-to-be-pushed
string = b''.join(array)

# Maximum amount that we can adjust SP by at once is 4095,
# which seems like a safe maximum.
if len(array) * 8 > 4095:
    raise Exception("Array size is too large (%i), max=4095" % len(array))
%>\
    /* push argument array ${repr(array)} */
    ${shellcraft.pushstr(string, register1=register1, register2=register2)}

    /* push null terminator */
    ${shellcraft.mov(register1, 0)}
    str ${register1}, [sp, #-8]!

    /* push pointers onto the stack */
%for i, value in enumerate(reversed(array)):
   ${shellcraft.mov(register1, (i+1)*8 + string.index(value))}
   add ${register1}, sp, ${register1}
   str ${register1}, [sp, #-8]! /* ${array[-i]} */
%endfor

    /* set ${reg} to the current top of the stack */
    ${shellcraft.mov(reg,'sp')}
