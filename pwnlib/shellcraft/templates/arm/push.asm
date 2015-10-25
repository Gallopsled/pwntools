<% from pwnlib import constants %>
<% from pwnlib.util import lists, packing, fiddling %>
<% from pwnlib.shellcraft.arm import mov %>
<%page args="word, register='r12'"/>
<%docstring>
Pushes a 32-bit integer onto the stack.  Uses r12 as a temporary register.

r12 is defined as the inter-procedural scartch register ($ip),
so this should not interfere with most usage.

Args:
    word (int, str):
        The word to push
    tmpreg (str):
        Register to use as a temporary register.  R7 is used by default.

</%docstring>
    ${mov(register,word)}
    push {${register}}
