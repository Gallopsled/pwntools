<% from pwnlib.shellcraft import amd64 %>
<%page args="string, sock = '1'"/>
<%docstring>Writes a string to a file descriptor</%docstring>

${amd64.pushstr(string, append_null = False)}
${amd64.linux.syscall('SYS_write', sock, 'rsp', len(string))}
