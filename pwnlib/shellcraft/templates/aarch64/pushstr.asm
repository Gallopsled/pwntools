<% from pwnlib.util import lists, packing, fiddling %>
<% from pwnlib import shellcraft %>
<%page args="string, append_null = True, register1='x14', register2='x15', pretty=None"/>
<%docstring>
Pushes a string onto the stack.

r12 is defined as the inter-procedural scratch register ($ip),
so this should not interfere with most usage.

Args:
    string (str): The string to push.
    append_null (bool): Whether to append a single NULL-byte before pushing.
    register (str): Temporary register to use.  By default, R7 is used.

Examples:

    >>> print(shellcraft.pushstr("Hello!").rstrip())
        /* push 'Hello!\x00' */
        /* Set x14 = 36762444129608 = 0x216f6c6c6548 */
        mov  x14, #25928
        movk x14, #27756, lsl #16
        movk x14, #8559, lsl #0x20
        str x14, [sp, #-16]!
    >>> print(shellcraft.pushstr("Hello, world!").rstrip())
        /* push 'Hello, world!\x00' */
        /* Set x14 = 8583909746840200520 = 0x77202c6f6c6c6548 */
        mov  x14, #25928
        movk x14, #27756, lsl #16
        movk x14, #11375, lsl #0x20
        movk x14, #30496, lsl #0x30
        /* Set x15 = 143418749551 = 0x21646c726f */
        mov  x15, #29295
        movk x15, #25708, lsl #16
        movk x15, #33, lsl #0x20
        stp x14, x15, [sp, #-16]!
    >>> print(shellcraft.pushstr("Hello, world, bienvenue").rstrip())
        /* push 'Hello, world, bienvenue\x00' */
        /* Set x14 = 8583909746840200520 = 0x77202c6f6c6c6548 */
        mov  x14, #25928
        movk x14, #27756, lsl #16
        movk x14, #11375, lsl #0x20
        movk x14, #30496, lsl #0x30
        /* Set x15 = 7593667296735556207 = 0x6962202c646c726f */
        mov  x15, #29295
        movk x15, #25708, lsl #16
        movk x15, #8236, lsl #0x20
        movk x15, #26978, lsl #0x30
        stp x14, x15, [sp, #-16]!
        /* Set x14 = 28558089656888933 = 0x65756e65766e65 */
        mov  x14, #28261
        movk x14, #25974, lsl #16
        movk x14, #30062, lsl #0x20
        movk x14, #101, lsl #0x30
        str x14, [sp, #-16]!
    >>> print(shellcraft.pushstr("Hello, world, bienvenue!").rstrip())
        /* push 'Hello, world, bienvenue!\x00' */
        /* Set x14 = 8583909746840200520 = 0x77202c6f6c6c6548 */
        mov  x14, #25928
        movk x14, #27756, lsl #16
        movk x14, #11375, lsl #0x20
        movk x14, #30496, lsl #0x30
        /* Set x15 = 7593667296735556207 = 0x6962202c646c726f */
        mov  x15, #29295
        movk x15, #25708, lsl #16
        movk x15, #8236, lsl #0x20
        movk x15, #26978, lsl #0x30
        stp x14, x15, [sp, #-16]!
        /* Set x14 = 2406458692908510821 = 0x2165756e65766e65 */
        mov  x14, #28261
        movk x14, #25974, lsl #16
        movk x14, #30062, lsl #0x20
        movk x14, #8549, lsl #0x30
        mov  x15, xzr
        stp x14, x15, [sp, #-16]!
</%docstring>
<%
if append_null and not string.endswith('\x00'):
    string += '\x00'

pretty_string = pretty or shellcraft.pretty(string)

while len(string) % 8:
    string += '\x00'

# Unpack everything into integers, and group them by twos
# so we may use STP to store multiple in a single instruction
words = packing.unpack_many(string)
pairs = lists.group(2, words)

# The stack must be 16-byte aligned
total = len(pairs) * 16

offset = 0
%>\
    /* push ${pretty_string} */
%for i,pair in enumerate(pairs):
    ${shellcraft.mov(register1, pair[0])}
  %if len(pair) == 1:
    str ${register1}, [sp, #-16]!
  %else:
    ${shellcraft.mov(register2, pair[1])}
    stp ${register1}, ${register2}, [sp, #-16]!
  %endif
%endfor
