<% from pwnlib.shellcraft.i386.linux import dup2 %>
<% from pwnlib.shellcraft.i386 import setregs %>
<% from pwnlib.shellcraft import common %>
<%page args="sock = 'ebp'"/>
<%docstring>
Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr
</%docstring>
<%
  looplabel = common.label("loop")
%>

    /* dup() file descriptor ${sock} into stdin/stdout/stderr */
    ${setregs({'ebx': sock, 'ecx': 2})}
${looplabel}:
    ${dup2('ebx', 'ecx')}
    dec ecx
    jns ${looplabel}
