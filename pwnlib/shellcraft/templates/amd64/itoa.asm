<%
from pwnlib.shellcraft import pretty, value, common, registers
from pwnlib.shellcraft.amd64 import mov, pushstr
from pwnlib import constants
%>
<%docstring>
Converts an integer into its string representation, and pushes it
onto the stack.

Arguments:
    v(str, int):
        Integer constant or register that contains the value to convert.
    alloca

Example:

    >>> sc = shellcraft.amd64.mov('rax', 0xdeadbeef)
    >>> sc += shellcraft.amd64.itoa('rax')
    >>> sc += shellcraft.amd64.linux.write(1, 'rsp', 32)
    >>> run_assembly(sc).recvuntil('\x00')
    '3735928559\x00'
</%docstring>
<%page args="v, buffer='rsp', allocate_stack=True"/>
<%
itoa_loop = common.label('itoa_loop')
size_loop = common.label('size_loop')
assert v in registers.amd64
%>\
    /* atoi(${pretty(v,0)}) */
%if allocate_stack and buffer=='rsp':
    sub rsp, 0x10
%endif
## We need to know how long the string is, in order for
## the beginning of the string to be *exactly* at rsp.
    ${mov('rdi', buffer)}
    ${mov('rax', v)}
    push rax /* save for later */
${size_loop}:
    ${mov('rdx', 0)}
    ${mov('rcx', 10)}
    div rcx
    inc rdi
    test rax, rax
    jnz ${size_loop}
    dec rdi
## Now we begin the actual division process
    pop rax
 ${itoa_loop}:
    ${mov('rdx', 0)}
## rcx is already 10
    div rcx
    add  dl, ${ord('0')}
    mov  BYTE PTR [rdi], dl
    dec  rdi
    test rax, rax
    jnz  ${itoa_loop}
## null terminate
    ${mov('rdx', 0)}
    mov  BYTE PTR [rdi], dl
    inc  rdi
