<% from pwnlib import constants %>
<% from pwnlib.util import lists, packing, fiddling %>
<%page args="string, append_null = True"/>
<%docstring>
Pushes a DWORD onto the stack.

Args:
  word (int, str): The word to push
</%docstring>
<%
# Try to get the absolute value of 'word' to determine if it can be pushed
# Guess at register names
word =

with ctx.local(arch = 'amd64'):
    try:
        src = constants.eval(src)
    except:
        log.error("Could not figure out the value of %r" % src)

if not isinstance(word, int):
    try:
        value =

if isinstance(word, int):
    if word <= 0xffff:
        print "push %#x" % word
    elif isinstance(word, int):
    print push(word)

%>

${mov('r0',word)}
push r0