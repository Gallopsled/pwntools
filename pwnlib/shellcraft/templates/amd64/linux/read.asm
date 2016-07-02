<% from pwnlib.shellcraft import amd64 %>
<%page args="fd=0, buffer='rsp', count=8"/>
<%docstring>
Reads data from the file descriptor into the provided buffer.
This is a one-shot and does not fill the request.
</%docstring>

    ${amd64.linux.syscall('SYS_read', fd, buffer, count)}
