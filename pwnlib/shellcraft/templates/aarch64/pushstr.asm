<% from pwnlib.util import lists, packing, fiddling %>
<% from pwnlib.shellcraft.aarch64 import mov %>
<%page args="string, append_null = True, register='r12'"/>
<%docstring>
Pushes a string onto the stack.

r12 is defined as the inter-procedural scratch register ($ip),
so this should not interfere with most usage.

Args:
    string (str): The string to push.
    append_null (bool): Whether to append a single NULL-byte before pushing.
    register (str): Temporary register to use.  By default, R7 is used.

Examples:

    >>> print shellcraft.aarch64.pushstr("Hello!").rstrip()
        /* push 'Hello!\x00\x00' */
        sub sp, sp, #16
        /* Set x0 = 36762444129608 = 0x216f6c6c6548 */
        mov  x0, #25928
        movk x0, #27756, lsl #16
        movk x0, #8559, lsl #0x20
        stur x0, [sp, #16 * 0]

</%docstring>
<%
if append_null:
    string += '\x00'

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
    /* push ${repr(string)} */
    sub sp, sp, #${total}
%for i,pair in enumerate(pairs):
    ${mov('x0', pair[0])}
  %if len(pair) == 1:
    stur x0, [sp, #16 * ${i}]
  %else:
    ${mov('x1', pair[1])}
    stp x0, x1, [sp, #16 * ${i}]
  %endif
%endfor
