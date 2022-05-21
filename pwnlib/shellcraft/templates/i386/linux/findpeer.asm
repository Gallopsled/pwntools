<% from pwnlib.shellcraft import common %>
<% from socket import htons %>
<%page args="port = None"/>
<%docstring>
Args: port (defaults to any port)
    Finds a socket, which is connected to the specified port.
    Leaves socket in ESI.
</%docstring>
<%
  findpeer = common.label("findpeer")
  looplabel = common.label("loop")
%>
${findpeer}:
    push -1
    push SYS_socketcall_getpeername
    mov ebp, esp
    pop ebx
    pop esi

${looplabel}:
    push SYS_socketcall
    pop eax

    inc esi
    lea ecx, [esp-32]

    push 4
    pushad

    int 0x80
% if port is None:
    test eax, eax
    popad
    pop edx
    jnz ${looplabel}
% else:
    popad
    pop edx
    shr eax, 16
    cmp ax, ${htons(int(port))}
    jne ${looplabel}
%endif
