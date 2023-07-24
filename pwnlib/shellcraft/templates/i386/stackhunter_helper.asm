<%page args="cookie = 0xe4fffc75"/>
<%docstring>
    stackhunter_helper(cookie = 0xe4fffc75)

    The helper for the stackhunter, which prepends the cookie
    at different alignments.

Example:

    >>> with context.local(arch='i386'):
    ...    print(enhex(asm(shellcraft.stackhunter_helper())))
    75fcffe43d75fcffe43d75fcffe43d75fcffe4
</%docstring>
    .int ${'%#x' % cookie}
    cmp eax, ${'%#x' % cookie}
    cmp eax, ${'%#x' % cookie}
    cmp eax, ${'%#x' % cookie}
