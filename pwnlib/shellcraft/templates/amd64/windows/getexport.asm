<%
    from pwnlib.shellcraft import amd64, pretty
    from pwnlib.util.packing import u64, _need_bytes
%>
<%docstring>Find the address of an exported function in a dll
by manually iterating through the PE export table.

Args:
    function_name (str): The name of the function to find.
    dll(str): The name of the DLL to find the function in.
    dest (str): The register to load the function address into.
</%docstring>
<%page args="function_name,dll='kernel32.dll',dest='rax'"/>
<%
function_name = _need_bytes(function_name)
dll = _need_bytes(dll)
if len(function_name) > 8:
    raise ValueError('function_name must be <= 8 bytes')
assert dll == b'kernel32.dll'
%>
    ${amd64.windows.kernel32base('rbx')} /* rbx = kernel32.dll PE base */
    mov r8d, [rbx + 0x3c]
    mov rdx, r8
    add rdx, rbx
    ${amd64.mov('r9', 0x88)}
    add rdx, r9
    mov r8d, [rdx]
    add r8, rbx /* r8 = export table */
    mov esi, [r8 + 0x20]
    add rsi, rbx /* rsi = names table */
    xor rcx, rcx
% if len(function_name) <= 8:
    mov r9, ${pretty(u64(function_name.ljust(8, b'\x00')))}
% else:
    ${amd64.pushstr(function_name)}
    mov r9, rsp
% endif

    /* Loop through the names table */
    FindFunction:
        inc rcx
        mov eax, [rsi + rcx * 4]
        add rax, rbx
        ## TODO: implement strcmp properly for function names > 8 bytes
        cmp qword ptr [rax], r9
        jnz FindFunction

    mov esi, [r8 + 0x24]
    add rsi, rbx /* rsi = ordinals table */
    mov cx, [rsi + rcx * 2]
    mov esi, [r8 + 0x1c]
    add rsi, rbx /* rsi = address table */
    mov eax, [rsi + rcx * 4]
    add rax, rbx /* rax = function address */
    mov ${dest}, rax
