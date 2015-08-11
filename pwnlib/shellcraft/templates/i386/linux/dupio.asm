<% from pwnlib.shellcraft.i386.linux import dup2 %>
<% from pwnlib.shellcraft.i386 import mov %>
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
    ${mov('ebx', sock)}
    ${mov('ecx', 3)}
${looplabel}:
    dec ecx

    ${dup2('ebx', 'ecx')}
    jnz ${looplabel}
