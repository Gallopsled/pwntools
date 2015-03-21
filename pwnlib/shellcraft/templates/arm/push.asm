<% from pwnlib import constants %>
<% from pwnlib.util import lists, packing, fiddling %>
<% from pwnlib.shellcraft.arm import mov %>
<%page args="word"/>
<%docstring>
Pushes a 32-bit integer onto the stack.  Uses R7 as a temporary register.

Args:
  word (int, str): The word to push
</%docstring>
% if isinstance(word, int) and word < 0xffff:
    push ${hex(word)}
% else:
    ${mov('r7',word)}
    push {r7}
% endif