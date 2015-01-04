<% from pwnlib.shellcraft import amd64 %>
<%docstring>Execute /bin/sh</%docstring>

${amd64.pushstr("/bin///sh")}

${amd64.syscall('SYS_execve', 'rsp', 0, 0)}
