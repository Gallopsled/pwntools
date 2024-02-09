<%
  from pwnlib import shellcraft
%>
<%page args="filename, flags='O_RDONLY', mode='rdx'"/>
<%docstring>
Opens a file
</%docstring>
    ${shellcraft.pushstr(filename)}
    ${shellcraft.syscall('SYS_open', 'rsp', flags, mode)}
