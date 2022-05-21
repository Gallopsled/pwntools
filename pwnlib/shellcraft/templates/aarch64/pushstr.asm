<% from pwnlib.util import lists, packing, fiddling %>
<% from pwnlib import shellcraft %>
<% import six %>
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

    >>> string = "Hello, world!"
    >>> assembly = shellcraft.pushstr(string)
    >>> assembly += shellcraft.write(1, 'sp', len(string))
    >>> assembly += shellcraft.exit()
    >>> ELF.from_assembly(assembly).process().recvall()
    b'Hello, world!'

    >>> string = "Hello, world! This is a long string! Wow!"
    >>> assembly = shellcraft.pushstr(string)
    >>> assembly += shellcraft.write(1, 'sp', len(string))
    >>> assembly += shellcraft.exit()
    >>> ELF.from_assembly(assembly).process().recvall()
    b'Hello, world! This is a long string! Wow!'
</%docstring>
<%
if isinstance(string, six.text_type):
    string = string.encode('utf-8')

if append_null and not string.endswith(b'\x00'):
    string += b'\x00'

pretty_string = pretty or shellcraft.pretty(string)

while len(string) % 8:
    string += b'\x00'

# Unpack everything into integers, and group them by twos
# so we may use STP to store multiple in a single instruction
words = packing.unpack_many(string)
pairs = lists.group(2, words)

pairs = pairs[::-1]

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
