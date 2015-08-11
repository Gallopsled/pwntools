<%
    from pwnlib.shellcraft import common
    from pwnlib.shellcraft.mips.linux import fork, exit
%>
<%page args=""/>
<%docstring>
Attempts to fork.  If the fork is successful, the parent exits.
</%docstring>
<%
dont_exit = common.label('forkexit')
%>
    ${fork()}
    blez $v0, ${dont_exit}
    ${exit(0)}
${dont_exit}:
