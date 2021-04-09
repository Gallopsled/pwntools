<% from pwnlib.shellcraft import amd64, pretty %>
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
<%page args="reg, array"/>
<%
if isinstance(array, (str)):
    array = [array]

array_str = ''

# Normalize all of the arguments' endings
array      = [arg.rstrip('\x00') + '\x00' for arg in array]
array_str  = ''.join(array)

word_size = 8
offset = len(array_str) + word_size

%>\
    /* push argument array ${pretty(array, False)} */
    ${amd64.pushstr(array_str)}
    ${amd64.mov(reg, 0)}
    push ${reg} /* null terminate */
% for i,arg in enumerate(reversed(array)):
    ${amd64.mov(reg, offset + word_size*i - len(arg))}
    add ${reg}, rsp
    push ${reg} /* ${pretty(arg, False)} */
    <% offset -= len(arg) %>\
% endfor
    ${amd64.mov(reg,'rsp')}
