<% from pwnlib.shellcraft import common, amd64 %>
<%page args="sock = 'rbp'"/>
<%docstring>
Args: [sock (imm/reg) = rbp]
    Duplicates sock to stdin, stdout and stderr
</%docstring>
<%
  looplabel = common.label("loop")
%>

    /* dup() file descriptor ${sock} into stdin/stdout/stderr */
    ${amd64.setregs({'rdi': sock, 'rsi': 2})}
${looplabel}:
    ${amd64.linux.dup2('rdi', 'rsi')}
    dec rsi
    jns ${looplabel}
