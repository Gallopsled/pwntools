<% from pwnlib.shellcraft import common %>
<%page args="sock = 'ebp'"/>
<%docstring>
Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr
</%docstring>
<%
  dup       = common.label("dup")
  looplabel = common.label("loop")
%>

${dup}:
        push ${sock}
        pop ebx
        push 3
        pop ecx

${looplabel}:
        dec ecx
        push SYS_dup2
        pop eax
        int 0x80
        jnz ${looplabel}
