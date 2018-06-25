<% from pwnlib.shellcraft import common, amd64 %>
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

    /* dup() file descriptor ${sock} into stdin/stdout/stderr */
${dup}:
    ${amd64.mov('rbp', sock)}

    push 3
${looplabel}:
    pop rsi
    dec rsi
    js ${after}
    push rsi

    ${amd64.linux.syscall('SYS_dup2', 'rbp', 'rsi')}

    jmp ${looplabel}
${after}:
