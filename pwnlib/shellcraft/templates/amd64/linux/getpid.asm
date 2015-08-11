<% from pwnlib.shellcraft import amd64 %>
<%docstring>Retrieve the current PID</%docstring>

${amd64.linux.syscall('SYS_getpid')}
