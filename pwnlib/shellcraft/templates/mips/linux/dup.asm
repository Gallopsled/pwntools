<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.mips.linux import dup2 %>
<%page args="sock = '$s0'"/>
<%docstring>
Args: [sock (imm/reg) = s0]
    Duplicates sock to stdin, stdout and stderr
</%docstring>
<%
   dup       = common.label("dup")
%>

    /* dup() file descriptor ${sock} into stdin/stdout/stderr */
${dup}:
    ${dup2(sock, 2)}
    ${dup2(sock, 1)}
    ${dup2(sock, 0)}

