<% from pwnlib.shellcraft import common %>
<%page args="clear_ebx = True, fix_null = False"/>
<%docstring>Calls mprotect(page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) for every page.

It takes around 0.3 seconds on my box, but your milage may vary.

Args:
  clear_ebx(bool): If this is set to False, then the shellcode will assume that ebx has already been zeroed.
  fix_null(bool): If this is set to True, then the NULL-page will also be mprotected at the cost of slightly larger shellcode
</%docstring>
<% label = common.label("mprotect_loop") %>

%if clear_ebx:
    xor ebx, ebx
%endif
%if fix_null:
    xor ecx, ecx
%endif
${label}:
    push PROT_READ | PROT_WRITE | PROT_EXEC
    pop edx
    push SYS_mprotect
    pop eax
    int 0x80
    xor ecx, ecx
    mov ch, 0x10
    add ebx, ecx
    jnz ${label}
