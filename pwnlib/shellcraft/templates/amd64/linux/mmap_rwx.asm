<% from pwnlib.shellcraft import amd64 %>
<%page args="size = 0x1000, protection = 7, address = None"/>
<%docstring>Maps some memory</%docstring>
<%
    if address:
        flags = 'MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED'
    else:
        flags = 'MAP_PRIVATE | MAP_ANONYMOUS'
%>
    ${amd64.linux.mmap(address, size, protection,flags, 0, 0)}

