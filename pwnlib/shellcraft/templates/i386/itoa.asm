<%
from pwnlib.shellcraft import pretty, common, registers
from pwnlib.shellcraft.i386 import mov, pushstr
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

    >>> sc = shellcraft.i386.mov('eax', 0xdeadbeef)
    >>> sc += shellcraft.i386.itoa('eax')
    >>> sc += shellcraft.i386.linux.write(1, 'esp', 32)
    >>> run_assembly(sc).recvuntil('\x00')
    '3735928559\x00'
</%docstring>
<%page args="v, buffer='esp', allocate_stack=True"/>
<%
itoa_loop = common.label('itoa_loop')
size_loop = common.label('size_loop')

assert v in registers.i386
%>\
    /* atoi(${pretty(v,0)}) */
%if allocate_stack and buffer=='esp':
    sub esp, 0x10
%endif
## We need to know how long the string is, in order for
## the beginning of the string to be *exactly* at esp.
    ${mov('edi', buffer)}
    ${mov('eax', v)}
    push eax /* save for later */
${size_loop}:
    ${mov('edx', 0)}
    ${mov('ecx', 10)}
    div ecx
    inc edi
    test eax, eax
    jnz ${size_loop}
    dec edi
## Now we begin the actual division process
    pop eax
 ${itoa_loop}:
    ${mov('edx', 0)}
## ecx is already 10
    div ecx
    add  dl, ${ord('0')}
    mov  BYTE PTR [edi], dl
    dec  edi
    test eax, eax
    jnz  ${itoa_loop}
## null terminate
    ${mov('edx', 0)}
    mov  BYTE PTR [edi], dl
    inc  edi
