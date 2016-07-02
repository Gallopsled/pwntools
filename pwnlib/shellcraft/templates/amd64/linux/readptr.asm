<% from pwnlib.shellcraft import amd64 %>
<%page args="fd=0, target_reg='rdx'"/>
<%docstring>Reads 8 bytes into the specified register</%docstring>

    push 1
    ${amd64.linux.read(fd, 'rsp', 8)}
    pop ${target_reg}
