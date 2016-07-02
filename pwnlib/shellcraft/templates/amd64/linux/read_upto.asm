<% from pwnlib.shellcraft import amd64 %>
<%page args="fd=0, buffer='rsp', sizereg='rdx'"/>
<%docstring>Reads up to N bytes 8 bytes into the specified register</%docstring>

${amd64.linux.readptr(sizereg)}
${amd64.linux.read(fd, buffer, sizereg)}
