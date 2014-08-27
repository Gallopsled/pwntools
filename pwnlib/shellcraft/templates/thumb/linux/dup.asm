<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.thumb import mov %>
<%page args="sock = 'r6'"/>
<%docstring>
Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr
</%docstring>
<%
  dup       = common.label("dup")
  looplabel = common.label("loop")
%>
${dup}:
        ${mov('r1', 3)}
        ${mov('r7', 'SYS_dup2')}

${looplabel}:
        ${mov('r0', sock)}
        sub r1, #1
        svc 1
        bne ${looplabel}
