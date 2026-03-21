<%
    from pwnlib.shellcraft import amd64, common, pretty
    from pwnlib.util.packing import u64, _need_bytes
%>
<%docstring>Find the address of an exported function in a dll
by manually iterating through the PE export table.

The dll must be `b'kernel32.dll'` or `b'ntdll.dll'` at the moment.
Behavior is undefined if the function is not found.

Args:
    function_name (bytes): The name of the function to find.
    dll(bytes): The name of the DLL to find the function in.
    dest (str): The register to load the function address into.
</%docstring>
<%page args="function_name,dll=b'kernel32.dll',dest='rax'"/>
<%
function_name = _need_bytes(function_name)
dll = _need_bytes(dll)
assert dll in (b'kernel32.dll', b'ntdll.dll')
find_function_loop = common.label('find_function').strip()
%>
% if dll == b'kernel32.dll':
    ${amd64.windows.kernel32base('rbx')} /* rbx = kernel32.dll PE base */
% elif dll == b'ntdll.dll':
    ${amd64.windows.ntdllbase('rbx')} /* rbx = ntdll.dll PE base */
% endif
    mov r8d, [rbx + 0x3c]
    mov rdx, r8
    add rdx, rbx
    ${amd64.mov('r9', 0x88)}
    add rdx, r9
    mov r8d, [rdx]
    add r8, rbx /* r8 = export table */
    mov edx, [r8 + 0x20]
    add rdx, rbx /* rdx = names table */
% if len(function_name) <= 8:
    mov r9, ${pretty(u64(function_name.ljust(8, b'\x00')))}
% else:
    ${amd64.pushstr(function_name)}
    mov r9, rsp
% endif
    push r8
    xor r8, r8

    /* Loop through the names table */
    ${find_function_loop}:
        inc r8
        mov eax, [rdx + r8 * 4]
        add rax, rbx
        ## strcmp
        % if len(function_name) <= 8:
        cmp qword ptr [rax], r9
        % else:
        ${amd64.setregs({
            'rdi': 'rax',
            'rsi': 'r9',
            'rcx': len(function_name),
        })}
        repe cmpsb
        movzx rax, byte ptr [rsi-1]
        movzx rcx, byte ptr [rdi-1]
        sub rax, rcx
        % endif
        jnz ${find_function_loop}

    ## Assume we find the function, we'll crash walking past the
    ## end of the names table otherwise.
    mov rcx, r8
    pop r8
    mov esi, [r8 + 0x24]
    add rsi, rbx /* rsi = ordinals table */
    mov cx, [rsi + rcx * 2]
    mov esi, [r8 + 0x1c]
    add rsi, rbx /* rsi = address table */
    mov eax, [rsi + rcx * 4]
    add rax, rbx /* rax = function address */
    ${amd64.mov(dest, 'rax')}
