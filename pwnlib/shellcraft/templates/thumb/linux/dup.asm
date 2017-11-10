<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.thumb import mov %>
<%page args="sock = 'r6'"/>
<%docstring>
Args: [sock (imm/reg) = r6]
    Duplicates sock to stdin, stdout and stderr
</%docstring>
<%
  dup       = common.label("dup")
  looplabel = common.label("loop")
%>
    /* dup() file descriptor ${sock} into stdin/stdout/stderr */
${dup}:
        ${mov('r1', 2)}
        ${mov('r7', 'SYS_dup2')}

${looplabel}:
        ${mov('r0', sock)}
        svc 1
        subs r1, #1
        bpl ${looplabel}
