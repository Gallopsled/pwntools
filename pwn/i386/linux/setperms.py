def setperms(src = 's', dst = 'res'):
    """Args: [src(imm/reg/r/e/s) = 's'], [dst(r/e/s/combi) = 'res']
    Sets the real, effective and/or saved UID.
    The source can be either the a number/register or the real, effective or saved UID.
"""

    lookup = {'r': 'ebx', 'e': 'ecx', 's': 'edx'}

    res = []

    def p(s):
        res.append(s)

    if src == 'r':
        p('push SYS_getuid')
        p('pop eax')
        p('int 0x80')
        for k in dst:
            p('mov %s, eax' % lookup[k])
    elif src == 'e':
        p('push SYS_geteuid')
        p('pop eax')
        p('int 0x80')
        for k in dst:
            p('mov %s, eax' % lookup[k])
    elif src == 's':
        p('mov edx, esp')
        p('push SYS_getresuid')
        p('mov ebx, esp')
        p('mov ecx, esp')
        p('pop eax')
        p('int 0x80')
        p('pop %s' % lookup[dst[0]])
        for k in dst[1:]:
            p('mov %s, %s' % (lookup[k], lookup[dst[0]]))
    elif isinstance(src, int) and -128 <= src <= 127:
        p('push %s' % src)
        p('pop %s' % lookup[dst[0]])
        for k in dst[1:]:
            p('mov %s, %s' % (lookup[k], lookup[dst[0]]))
    else:
        p('mov %s, %s' % (lookup[dst[0]], src))
        for k in dst[1:]:
            p('mov %s, %s' % (lookup[k], lookup[dst[0]]))

    first = True
    for k,v in lookup.items():
        if k not in dst:
            if first == True:
                first = v
                p('push -1')
                p('pop %s' % v)
            else:
                p('mov %s, %s' % (v, first))

    p('push SYS_setresuid')
    p('pop eax')
    p('int 0x80')

    return ''.join('\n    ' + s for s in res)
