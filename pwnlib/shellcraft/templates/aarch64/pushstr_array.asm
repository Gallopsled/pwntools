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
</%docstring>
<%page args="reg, array, register1='x14', register2='x15'"/>
<%
if isinstance(array, (binary_type, text_type)):
    array = [array]

# Normalize all of the arguments' endings
array = [arg.rstrip(b'\x00') + b'\x00' for arg in array]

# Maximum amount that we can adjust SP by at once is 4095,
# which seems like a safe maximum.
if len(array) * 8 > 4095:
    raise Exception("Array size is too large (%i), max=4095" % len(array))

# Join them into one big string that can be pushed
array_str = b''.join(array)

# Create a listing of offsets from what will be the "top" of the stack.
num_pointers = len(array)

# Account for the NULL terminator
num_pointers += 1

while num_pointers % 2 != 0:
    num_pointers += 1

# Offset from the 'top' of the stack, to the data pointed at
sp_to_data = num_pointers * ctx.bytes

# List of amounts to subtract from $SP
offsets = {}
for i, value in reversed(list(enumerate(array))):
    offsets[i] = sp_to_data + len(array_str) - len(array[i])

# If the array length is ODD we can sneak in our null terminator at the end
if len(array) % 2 == 1:
    offsets[len(offsets)] = 'sp'

sorted_offsets = []
for key in sorted(offsets):
    sorted_offsets.append(offsets[key])

# Load the offsets into pairs
pairwise_offsets = group(2, sorted_offsets)
%>\
    /* push argument array ${repr(array)} */
    ${shellcraft.pushstr(array_str, register1=register1, register2=register2)}

    /* adjust the stack pointer to account for the array of pointers */
    sub sp, sp, ${num_pointers * ctx.bytes}

    /* push pointers onto the stack in pairs */
%for i, (a, b) in enumerate(pairwise_offsets):
    ${shellcraft.mov(register1, a)}
    ${shellcraft.mov(register2, b)}
    sub  ${register1}, sp, ${register1}
    sub  ${register2}, sp, ${register2}
    stp  ${register1}, ${register2}, [sp], ${i * 16}
%endfor
%if len(array[-1] != 'sp')

    /* set ${reg} to the current top of the stack */
    ${shellcraft.mov(reg,'sp')}
