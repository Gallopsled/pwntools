<% from pwnlib.shellcraft import amd64 %>
<% from pwnlib.constants.linux.amd64 import SYS_write %>
<%page args="string, sock = 'rbp'"/>
<%docstring>Writes a string to a file descriptor</%docstring>

${amd64.pushstr(string, append_null = False)}
${amd64.linux.syscall('SYS_write', sock, 'rsp', len(string))}
