<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.mips.linux import dup2 %>
<% from pwnlib.shellcraft.mips import mov %>
<%page args="sock = '$s0'"/>
<%docstring>
Args: [sock (imm/reg) = s0]
    Duplicates sock to stdin, stdout and stderr
</%docstring>
<%
   dup       = common.label("dup")
   looplabel = common.label("loop")
%>

    /* dup() file descriptor ${sock} into stdin/stdout/stderr */
${dup}:
    ${mov('$t0',2)}
${looplabel}:
    ${dup2(sock,'$t0')}
    bgtz $t0,${looplabel}
    addi $t0,-1
