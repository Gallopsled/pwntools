<%
  from pwnlib import shellcraft
%>
<%page args="filename, fd=1, length=0x4000"/>
<%docstring>
Opens a file and writes its contents to the specified file descriptor.
Uses an extra stack buffer and must know the length.
</%docstring>

    ${shellcraft.open(filename)}
    ${shellcraft.mov('rdx', length)}
    sub rsp, rdx
    ${shellcraft.read('rax', 'rsp', 'rdx')}
    ${shellcraft.write(fd, 'rsp', 'rax')}
