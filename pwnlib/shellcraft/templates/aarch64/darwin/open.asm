<%
  from pwnlib import shellcraft
%>
<%page args="filename, flags='O_RDONLY', mode='x3'"/>
<%docstring>
Opens a file
</%docstring>
    ${shellcraft.pushstr(filename)}
    ${shellcraft.syscall('SYS_open', 'sp', flags, mode)}
