<%
    from pwnlib.shellcraft import amd64, pretty
    from pwnlib.util.packing import _need_bytes
    from pwnlib.util.misc import align
%>
<%docstring>Find the address of an exported function
by calling kernel32::GetProcAddress.

Args:
    function_name(str): The name of the function to find.
    dll(str): The name of the DLL to find the function in.
    dest (str): The register to load the function address into.
</%docstring>
<%page args="function_name,dll='kernel32.dll',dest='rax'"/>
<%
function_name = _need_bytes(function_name)
dll = _need_bytes(dll)
assert dll == b'kernel32.dll'
%>

    ${amd64.windows.getexport(b'GetProcA', b'kernel32.dll', dest='rdi')}
    ${amd64.pushstr(function_name)}
    mov rdx, rsp
    ${amd64.windows.kernel32base(dest='rcx')}
    sub rsp, 0x30
    call rdi
    add rsp, ${pretty(0x30+align(8, len(function_name)))}
    mov ${dest}, rax
