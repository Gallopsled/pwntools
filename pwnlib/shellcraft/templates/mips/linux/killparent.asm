<%
    from pwnlib.shellcraft.mips.linux import getppid, kill
    from pwnlib.constants import SIGKILL
    from pwnlib.shellcraft.common import label
%>
<%docstring>
Kills its parent process until whatever the parent is (probably init)
cannot be killed any longer.
</%docstring>
<%
    killparent_loop = label('killparent')
%>
${killparent_loop}:
    ${getppid()}
    ${kill('$v0', SIGKILL)}
    beq $v0, $zero, ${killparent_loop}
