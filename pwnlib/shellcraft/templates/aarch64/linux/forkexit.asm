<%
    from pwnlib.shellcraft import common
    from pwnlib.shellcraft.aarch64.linux import fork, exit
%>
<%page args=""/>
<%docstring>
Attempts to fork.  If the fork is successful, the parent exits.
</%docstring>
<%
dont_exit = common.label('forkexit')
%>
    ${fork()}
    cmp x0, 1
    blt ${dont_exit}
    ${exit(0)}
${dont_exit}:
