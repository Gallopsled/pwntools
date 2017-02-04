
<%
    from pwnlib.shellcraft.aarch64.linux import syscall
%>
<%page args=""/>
<%docstring>
Invokes the syscall getpgrp.  See 'man 2 getpgrp' for more information.

Arguments:

</%docstring>

    ${syscall('SYS_getpgrp')}
