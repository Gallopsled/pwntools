<% from pwnlib.shellcraft import common %>
<%page args="sock = 'rbp'"/>
<%docstring>
Args: [sock (imm/reg) = rbp]
    Duplicates sock to stdin, stdout and stderr
</%docstring>
<%
  dup       = common.label("dup")
  looplabel = common.label("loop")
  after     = common.label("after")
%>


${dup}:
    % if sock != "rbp":
        push ${sock}
        pop rbp
    % endif

        push 3
${looplabel}:
        mov rdi, rbp
        pop rsi
        dec rsi
        js ${after}
        push rsi
        push SYS_dup2
        pop rax
        syscall
        jmp ${looplabel}
${after}: