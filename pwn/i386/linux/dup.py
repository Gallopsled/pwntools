def dup(sock = 'ebx'):
    """Arguments: [sock = EBX]
    Duplicates sock to stdin, stdout and stderr."""
    return """
        ;; Takes socket in ebx
dup:
        setfd ebx, %s
        push byte 3
        pop ecx
.loop:
        dec ecx
        push byte SYS_dup2
        pop eax
        int 0x80
        jnz .loop
""" % str(sock)
