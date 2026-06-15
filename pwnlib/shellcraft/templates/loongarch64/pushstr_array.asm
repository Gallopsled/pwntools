<% from pwnlib.shellcraft import loongarch64, pretty %>
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
    ${loongarch64.pushstr(array_str)}
    ${loongarch64.mov(reg, 0)}
    ${loongarch64.push(reg)}
% for i,arg in enumerate(reversed(array)):
    ${loongarch64.mov(reg, offset + word_size*i - len(arg))}
    addi.d   $${reg}, $sp, $${reg}
    ${loongarch64.push(reg)}
    <% offset -= len(arg) %>\
% endfor
    ${loongarch64.mov(reg,'sp')}
