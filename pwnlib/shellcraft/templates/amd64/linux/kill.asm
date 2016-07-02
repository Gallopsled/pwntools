<% from pwnlib.shellcraft import amd64 %>
<%page args="pid, signal = 'SIGKILL'"/>
<%docstring>Writes a string to a file descriptor</%docstring>

    ${amd64.linux.syscall('SYS_kill', pid, signal)}
