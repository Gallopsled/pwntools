import re

"""Args: Name of file. Shows the contents of specified file.

Uses /bin/cat unless use_sendfile is set to true.
If sendfile is used, the code segfaults after reading.
If the file doesn't exists, the code segfaults. """
def cat(filename = 'file', use_sendfile = False):
    pushstr = ''
    length = len(filename)
    off = length % 4

    pushnull = ''
    movnull = ''

    if off:
        m = re.match('(.*)(/.*$)', filename)
        if m:
            pushnull = 'push eax\n'
            filename = m.group(1) + '/' * (4 - off) + m.group(2)
        elif off < 3:
            pushnull = 'push eax\n'
            filename = './' + '/' * (2 - off) + filename
        else:
            filename += ' '
            pushnull = ''
            movnull = 'mov [ecx + %d], al\n' % length
    else:
        pushnull = 'push eax\n'
    for i in range(0, len(filename), 4):
        pushstr = 'push `%s`\n' % filename[i : i + 4] + pushstr
    if not use_sendfile:
        return """
            ; Clear registers
            xor eax, eax
            cdq
        
            ; Prepare args for /bin/cat
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
            
            ; Call sys_execve
            mov al, 0xb
            int 0x80
        """ % (pushnull, pushstr, movnull)
    else:
        return """
            ; Clear registers
            xor ecx, ecx
            imul ecx
            
            ; Call sys_open with read mode
            %s%s
            mov ebx, esp
            %s
            ;mov cl, 0x72 ; flags are bothersome
            mov al, 0x5
            int 0x80
        
            ; Call sys_sendfile to read file into stdout
            xor ebx, ebx
            mov ecx, eax
            
            ; xor eax, eax ; eax is probably low enough
            mov al, 0xbb
            ;mov esi, 0x7fffffff
            mov esi, edi ; size. edi is close enough.
            int 0x80
        """ % (pushnull, pushstr, movnull)

