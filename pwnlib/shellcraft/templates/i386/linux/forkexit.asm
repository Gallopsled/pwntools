<%
    from pwnlib.shellcraft import common
    from pwnlib.shellcraft.i386.linux import fork, exit
%>
<%page args=""/>
<%docstring>
Attempts to fork.  If the fork is successful, the parent exits.
</%docstring>
<%
dont_exit = common.label('forkexit')
%>
    ${fork()}
    cmp eax, 1
    jl ${dont_exit}
    ${exit(0)}
${dont_exit}:
